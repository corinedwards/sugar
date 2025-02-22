# frozen_string_literal: true

module Sugar
  class << self
    attr_writer :redis

    def aws_s3?
      if ENV.fetch("S3_BUCKET", nil) &&
         ENV.fetch("S3_KEY_ID", nil) &&
         ENV["S3_SECRET"]
        true
      else
        false
      end
    end

    def redis
      @redis ||= Redis.new(driver: :hiredis, url: redis_url)
    end

    def redis_url=(new_url)
      @redis = nil
      @config = nil
      @redis_url = new_url
    end

    def redis_url
      @redis_url ||= "redis://127.0.0.1:6379/1"
    end

    def config(_key = nil, *_args)
      @config ||= Configuration.new.tap(&:load)
    end

    def public_browsing?
      config.public_browsing
    end
  end
end
