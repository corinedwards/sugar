# encoding: utf-8

require 'digest/md5'

class ApplicationController < ActionController::Base

  include Authentication

  layout 'application'

  protect_from_forgery

  before_action :disable_xss_protection
  before_action :load_configuration
  before_action :set_time_zone
  before_action :set_section

  helper_method :viewed_tracker

  protected

  def disable_xss_protection
    # Disabling this is probably not a good idea, but the header
    # causes Chrome to choke when being redirected back after a submit
    # and the page contains an iframe.
    response.headers['X-XSS-Protection'] = "0"
  end

  # Renders an error
  def render_error(error, options={})
    options[:status] ||= error if error.kind_of?(Numeric)
    error_messages = {
      404 => 'Not found'
    }
    respond_to do |format|
      format.html   {options[:template] ||= "errors/#{error}"}
      format.xml    {options[:text] ||= error_messages[error]}
      format.json   {options[:text] ||= error_messages[error]}
    end
    render options
  end

  def viewed_tracker
    @viewed_tracker ||= ViewedTracker.new(current_user)
  end

  def respond_with_exchanges(exchanges)
    viewed_tracker.exchanges = exchanges
    respond_with(exchanges)
  end

  def load_configuration
    Sugar.config.load
  end

  def set_time_zone
    if current_user.try(&:time_zone)
      Time.zone = current_user.time_zone
    end
  end

  def require_s3
    unless Sugar.aws_s3?
      flash[:notice] = "Amazon Web Services not configured!"
      redirect_to root_url and return
    end
  end

  def set_section
    case self.class.to_s
    when 'UsersController'
      @section = :users
    when 'MessagesController'
      @section = :messages
    when 'InvitesController'
      @section = :invites
    when 'ConversationsController'
      @section = :conversations
    else
      @section = :discussions
    end
  end
end
