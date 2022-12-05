# frozen_string_literal: true

require "digest/sha1"

class PostsController < ApplicationController
  caches_page :count

  requires_authentication except: %i[count]
  requires_user except: %i[count since search]

  before_action :find_exchange, except: %i[search]
  before_action :verify_viewable, except: %i[search count]
  before_action :find_post, only: %i[edit update]
  before_action :find_post, only: %i[edit update]
  before_action :verify_editable, only: %i[edit update]
  before_action :require_and_set_search_query, only: %i[search]
  before_action :verify_postable, only: %i[create]

  after_action :mark_exchange_viewed, only: %i[since index]
  after_action :mark_conversation_viewed, only: %i[since index]
  # after_action :notify_mentioned, only: [:create]

  def index
    @page = params[:page] || 1
    @posts = @exchange.posts.page(@page, context: 0).for_view
    respond_to do |format|
      format.json do
        serializer = posts_serializer(@posts)
        render json: serializer.serialized_json
      end
    end
  end

  def count
    @count = @exchange.posts_count
    respond_to do |format|
      format.json { render json: { posts_count: @count }.to_json }
    end
  end

  def since
    @posts = @exchange.posts.limit(200).offset(params[:index]).for_view
    render layout: false if request.xhr?
  end

  def search
    @search_path = search_posts_path
    @posts = Post.search(search_query).page(params[:page])
  end

  def create
    create_post(post_params.merge(user: current_user))
  rescue URI::InvalidURIError => e
    render_post_error(e.message)
  end

  def update
    @post.update(post_params.merge(edited_at: Time.now.utc))

    post_url = polymorphic_url(@exchange,
                               page: @post.page,
                               anchor: "post-#{@post.id}")

    respond_to do |format|
      if @post.valid?
        format.html { redirect_to post_url }
        format.json { render json: @post }
      else
        format.html { render action: :edit }
        format.json { render json: @post, status: :unprocessable_entity }
      end
    end
  end

  def preview
    @post = @exchange.posts.new(post_params.merge(user: current_user))
    @post.fetch_images
    @post.body_html # Render post to trigger any errors
    render layout: false if request.xhr?
  rescue URI::InvalidURIError => e
    render_post_error(e.message)
  end

  def edit
    render layout: false if request.xhr?
  end

  private

  def create_post(create_params)
    @post = @exchange.posts.create(create_params)
    @exchange.reload

    exchange_url = polymorphic_url(@exchange,
                                   page: @exchange.last_page,
                                   anchor: "post-#{@post.id}")

    # if @exchange.is_a?(Conversation)
    #   ConversationNotifier.new(@post, exchange_url).deliver_later
    # end

    respond_to do |format|
      if @post.valid?
        format.html { redirect_to exchange_url }
        format.json { render json: @post, status: :created }
      else
        format.html { render action: :new }
        format.json { render json: @post, status: :unprocessable_entity }
      end
    end
  end

  def find_exchange
    @exchange = if params[:discussion_id]
                  Discussion.find(params[:discussion_id])
                elsif params[:conversation_id]
                  Conversation.find(params[:conversation_id])
                else
                  Exchange.find(params[:exchange_id])
                end
  end

  def find_post
    @post = Post.find(params[:id])
  end

  def mark_conversation_viewed
    return unless @exchange.is_a?(Conversation)

    current_user.mark_conversation_viewed(@exchange)
  end

  def mark_exchange_viewed
    return unless current_user? && @posts.any?

    current_user.mark_exchange_viewed(@exchange,
                                      @posts.last,
                                      (params[:index].to_i + @posts.length))
  end

  # def notify_mentioned
  #   if @post.valid? && @post.mentions_users?
  #     @post.mentioned_users.each do |mentioned_user|
  #       logger.info "Mentions: #{mentioned_user.username}"
  #     end
  #   end
  # end

  def post_params
    params.require(:post).permit(:body, :format)
  end

  def posts_serializer(posts)
    PostSerializer.new(
      posts,
      links: { self: paginated_json_path(posts.current_page),
               next: paginated_json_path(posts.next_page),
               previous: paginated_json_path(posts.previous_page) },
      include: %i[user]
    )
  end

  def search_query
    params[:query] || params[:q]
  end

  def render_post_error(msg)
    render plain: msg, status: :internal_server_error if request.xhr?
  end

  def require_and_set_search_query
    @search_query = search_query
    return if @search_query

    flash[:notice] = "No query specified!"
    redirect_to root_url
  end

  def verify_editable
    return if @post.editable_by?(current_user)

    flash[:notice] = "You don't have permission to edit that post!"
    redirect_to polymorphic_url(@exchange, page: @exchange.last_page)
  end

  def verify_postable
    return if @exchange.postable_by?(current_user)

    flash[:notice] = "This discussion is closed, " \
                     "you don't have permission to post here"
    redirect_to polymorphic_url(@exchange, page: @exchange.last_page)
  end

  def verify_viewable
    return if @exchange&.viewable_by?(current_user)

    flash[:notice] = "You don't have permission to view that discussion!"
    redirect_to root_url
  end
end
