# encoding: utf-8
require "logstash/namespace"
require "logstash/outputs/base"
require "logstash/errors"
require "zlib"

# This output writes events to files on disk. You can use fields
# from the event as parts of the filename and/or path.
#
# By default, this output writes one event per line in **json** format.
# You can customise the line format using the `line` codec like
# [source,ruby]
# output {
#  file {
#    path => ...
#    codec => line { format => "custom format: %{message}"}
#  }
# }
class LogStash::Outputs::File < LogStash::Outputs::Base
  concurrency :shared

  FIELD_REF = /%\{[^}]+\}/

  config_name "file"

  attr_reader :failure_path

  # The path to the file to write. Event fields can be used here,
  # like `/var/log/logstash/%{host}/%{application}`
  # One may also utilize the path option for date-based log
  # rotation via the joda time format. This will use the event
  # timestamp.
  # E.g.: `path => "./test-%{+YYYY-MM-dd}.txt"` to create
  # `./test-2013-05-29.txt`
  #
  # If you use an absolute path you cannot start with a dynamic string.
  # E.g: `/%{myfield}/`, `/test-%{myfield}/` are not valid paths
  config :path, :validate => :string, :required => true

  # Flush interval (in seconds) for flushing writes to log files.
  # 0 will flush on every message.
  config :flush_interval, :validate => :number, :default => 2

  # Gzip the output stream before writing to disk.
  config :gzip, :validate => :boolean, :default => false

  # If the generated path is invalid, the events will be saved
  # into this file and inside the defined path.
  config :filename_failure, :validate => :string, :default => '_filepath_failures'

  # If the configured file is deleted, but an event is handled by the plugin,
  # the plugin will recreate the file. Default => true
  config :create_if_deleted, :validate => :boolean, :default => true

  # Dir access mode to use. Note that due to the bug in jruby system umask
  # is ignored on linux: https://github.com/jruby/jruby/issues/3426
  # Setting it to -1 uses default OS value.
  # Example: `"dir_mode" => 0750`
  config :dir_mode, :validate => :number, :default => -1

  # File access mode to use. Note that due to the bug in jruby system umask
  # is ignored on linux: https://github.com/jruby/jruby/issues/3426
  # Setting it to -1 uses default OS value.
  # Example: `"file_mode" => 0640`
  config :file_mode, :validate => :number, :default => -1


  # How should the file be written?
  #
  # If `append`, the file will be opened for appending and each new event will
  # be written at the end of the file.
  #
  # If `overwrite`, the file will be truncated before writing and only the most
  # recent event will appear in the file.
  config :write_behavior, :validate => [ "overwrite", "append", "rotate" ], :default => "append"


  config :rotate_interval, :validate => :number, :default => 60 # minutes
  config :rotate_size, :validate => :number, :default => 100 # mb
  config :rotate_idle, :validate => :number, :default => 3600 # seconds
  config :rotate_extension, :validate => :string, :default => ".tmp"


  default :codec, "json_lines"

  def register
    require "fileutils" # For mkdir_p

    @files = {}
    @io_mutex = Mutex.new

    @path = File.expand_path(path)

    validate_path

    if path_with_field_ref?
      @file_root = extract_file_root
    else
      @file_root = File.dirname(path)
    end
    @failure_path = File.join(@file_root, @filename_failure)

    @flush_interval = @flush_interval.to_i
    if @flush_interval > 0
      @flusher = Interval.start(@flush_interval, -> { flush_pending_files })
    end

    @last_stale_cleanup_cycle = Time.now
    @stale_cleanup_interval = 10

    self.class.send(:alias_method, :writer, "behavior_#{@write_behavior}")
  end

  def multi_receive_encoded(events_and_encoded)
    encoded_by_path = Hash.new { |h, k| h[k] = [] }

    events_and_encoded.each do |event, encoded|
      file_output_path = event_path(event)
      encoded_by_path[file_output_path] << encoded
    end

    @io_mutex.synchronize do
      encoded_by_path.each do |path, chunks|
        writer(path, chunks)
      end

      periodic_close_stale_files
    end
  end

  def close
    @flusher.stop unless @flusher.nil?
    @io_mutex.synchronize do
      @logger.debug? &&  @logger.debug("Close: closing files")

      @files.each do |path, fd|
        begin
          fd.close
          @logger.debug? &&  @logger.debug("Closed file #{path}", :fd => fd)
        rescue Exception => e
          @logger.error("Exception while flushing and closing files.", :exception => e)
        end
      end
    end
  end

  private

  def behavior_overwrite(path, chunks)
    fd = open(path)
    fd.truncate(0)
    fd.seek(0, IO::SEEK_SET)
    fd.write(chunks.last)
    fd.flush unless @flusher && @flusher.alive?
  end

  def behavior_append(path, chunks)
    fd = open(path)
    chunks.each { |chunk| fd.write(chunk) }
    fd.flush unless @flusher && @flusher.alive?
  end

  def behavior_rotate(path, chunks)

  end

  def validate_path
    if (root_directory =~ FIELD_REF) != nil
      @logger.error("File: The starting part of the path should not be dynamic.", :path => @path)
      raise LogStash::ConfigurationError.new("The starting part of the path should not be dynamic.")
    end
  end

  def root_directory
    parts = @path.split(File::SEPARATOR).select { |item| !item.empty?  }
    if Gem.win_platform?
      # First part is the drive letter
      parts[1]
    else
      parts.first
    end
  end

  def inside_file_root?(log_path)
    target_file = File.expand_path(log_path)
    target_file.start_with?("#{@file_root.to_s}/")
  end

  def event_path(event)
    file_output_path = generate_filepath(event)
    if path_with_field_ref? && !inside_file_root?(file_output_path)
      @logger.warn("File: the event tried to write outside the files root, writing the event to the failure file",  :event => event, :filename => @failure_path)
      file_output_path = @failure_path
    elsif !@create_if_deleted && !exist?(file_output_path)
      file_output_path = @failure_path
    end
    @logger.debug? &&  @logger.debug("File, writing event to file.", :filename => file_output_path)

    file_output_path
  end

  def generate_filepath(event)
    event.sprintf(@path)
  end

  def path_with_field_ref?
    # we can memoize to optimize since path does not change
    @is_path_with_field_ref ||= (path =~ FIELD_REF)
  end

  def extract_file_root
    # this could also be memoized but is only called once in register
    parts = File.expand_path(path).split(File::SEPARATOR)
    parts.take_while { |part| part !~ FIELD_REF }.join(File::SEPARATOR)
  end

  # the back-bone of @flusher, our periodic-flushing interval.
  def flush_pending_files
    @io_mutex.synchronize do
      @logger.debug? && @logger.debug("Starting flush cycle")

      @files.each do |path, fd|
        @logger.debug? &&  @logger.debug("Flushing file", :path => path, :fd => fd)
        fd.flush
      end
    end
  rescue => e
    # squash exceptions caught while flushing after logging them
    @logger.error("Exception flushing files", :exception => e.message, :backtrace => e.backtrace)
  end

  # every 10 seconds or so (triggered by events, but if there are no events there's no point closing files anyway)
  def periodic_close_stale_files
    now = Time.now
    return unless now - @last_stale_cleanup_cycle >= @stale_cleanup_interval
    close_stale_files
    @last_stale_cleanup_cycle = now
  end

  def close_stale_files
    @logger.debug? &&  @logger.debug("Starting stale files cleanup cycle", :files => @files)
    inactive_files = @files.select { |path, fd| not fd.active }
    @logger.debug? &&  @logger.debug("%d stale files found" % inactive_files.count, :inactive_files => inactive_files)
    # puts("%d stale files found" % inactive_files.count, :inactive_files => inactive_files)
    inactive_files.each do |path, fd|
      @logger.info("Closing file %s" % path)
      # puts("Closing file %s" % path)
      if fd.class == Zlib::GzipWriter
        fd.close
        fd.to_io.close
      else
        fd.close
      end
      @files.delete(path)
    end
    # mark all files as inactive, a call to write will mark them as active again
    @files.each { |path, fd| fd.active = false }
  end

  def cached?(path)
    @files.include?(path) && !@files[path].nil?
  end

  def exit?(path)
    File.exist?(path)
  end

  def open(path)
    if exist?(path) && cached?(path)
      # puts("** not deleted and cached")
      return @files[path]
    end

    if !exist?(path)
      # puts("** is deleted #{path}")
      if @create_if_deleted
        @logger.debug? &&  @logger.debug("Required path was deleted, creating the file again", :path => path)
        @files.delete(path)
      else
        return @files[path] if cached?(path)
      end
    end

    @logger.info("Opening file", :path => path)

    dir = File.dirname(path)
    if !Dir.exist?(dir)
      @logger.info("Creating directory", :directory => dir)
      if @dir_mode != -1
        FileUtils.mkdir_p(dir, :mode => @dir_mode)
      else
        FileUtils.mkdir_p(dir)
      end
    end

    # work around a bug opening fifos (bug JRUBY-6280)
    stat = File.stat(path) rescue nil
    if stat && stat.ftype == "fifo"
      fd = java.io.FileWriter.new(java.io.File.new(path))
    else
      if @file_mode != -1
        fd = File.new(path, "a+", @file_mode)
      else
        fd = File.new(path, "a+")
      end
    end
    if gzip
      # puts("** new gzip writer")
      fd = Zlib::GzipWriter.new(fd)
    end

    @files[path] = IOWriter.new(fd)
  end

  def temp_rotate_path(path)
    path + @rotate_extension
  end

  def final_rotate_path(path, rotation_count)
    path + ".#{rotation_count}"
  end

  def safe_rotate(path, rotation_count = 0)
    i = rotation_count
    # we assume there is only one file output plugin per file pattern so no race condition in the rotation generation
    while File.exists?(final_rotate_path(path, i))
      i += 1
    end
    FileUtils.mv(temp_rotate_path(path), final_rotate_path(path, i))
  end

  def rotate_open(path)
    if cached?(path)
      return @files[path]
    end

    if exist?(temp_rotate_path)
      safe_rotate(path)
    end

    @logger.info("Opening file", :path => temp_rotate_path)

    dir = File.dirname(path)
    if !Dir.exist?(dir)
      @logger.info("Creating directory", :directory => dir)
      if @dir_mode != -1
        FileUtils.mkdir_p(dir, :mode => @dir_mode)
      else
        FileUtils.mkdir_p(dir)
      end
    end

    if @file_mode != -1
      fd = File.new(temp_rotate_path, "w", @file_mode)
    else
      fd = File.new(temp_rotate_path, "w")
    end

    if gzip
      # puts("** new gzip writer")
      fd = Zlib::GzipWriter.new(fd)
    end

    @files[path] = IOWriter.new(fd)
  end


  ##
  # Bare-bones utility for running a block of code at an interval.
  #
  class Interval
    ##
    # Initializes a new Interval with the given arguments and starts it before returning it.
    #
    # @param interval [Integer] (see: Interval#initialize)
    # @param procsy [#call] (see: Interval#initialize)
    #
    # @return [Interval]
    #
    def self.start(interval, procsy)
      self.new(interval, procsy).tap(&:start)
    end

    ##
    # @param interval [Integer]: time in seconds to wait between calling the given proc
    # @param procsy [#call]: proc or lambda to call periodically; must not raise exceptions.
    def initialize(interval, procsy)
      @interval = interval
      @procsy = procsy

      require 'thread' # Mutex, ConditionVariable, etc.
      @mutex = Mutex.new
      @sleeper = ConditionVariable.new
    end

    ##
    # Starts the interval, or returns if it has already been started.
    #
    # @return [void]
    def start
      @mutex.synchronize do
        return if @thread && @thread.alive?

        @thread = Thread.new { run }
      end
    end

    ##
    # Stop the interval.
    # Does not interrupt if execution is in-progress.
    def stop
      @mutex.synchronize do
        @stopped = true
      end

      @thread && @thread.join
    end

    ##
    # @return [Boolean]
    def alive?
      @thread && @thread.alive?
    end

    private

    def run
      @mutex.synchronize do
        loop do
          @sleeper.wait(@mutex, @interval)
          break if @stopped

          @procsy.call
        end
      end
    ensure
      @sleeper.broadcast
    end
  end
end

# wrapper class
class IOWriter
  attr_accessor :active

  def initialize(io)
    @io = io
  end

  def write(*args)
    @io.write(*args)
    @active = true
  end

  def flush
    @io.flush
    if @io.class == Zlib::GzipWriter
      @io.to_io.flush
    end
  end

  def method_missing(method_name, *args, &block)
    if @io.respond_to?(method_name)
      @io.send(method_name, *args, &block)
    else
      super
    end
  end
end
