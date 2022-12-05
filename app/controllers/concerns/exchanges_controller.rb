# frozen_string_literal: true

module ExchangesController
  extend ActiveSupport::Concern

  included do
    protect_from_forgery except: [:mark_as_read]
  end

  def search_posts
    @search_path = polymorphic_path([:search_posts, @exchange])
    @posts = @exchange.posts
                      .search_in_exchange(search_query)
                      .page(params[:page])
    render template: "exchanges/search_posts"
  end

  def show
    @page = params[:page] || 1
    @posts = @exchange.posts.page(@page, context: context).for_view

    mark_as_viewed!(@exchange, @posts.last,
                    (@posts.offset_value + @posts.count))

    respond_to do |format|
      format.html
      format.json do
        redirect_to(
          polymorphic_path([@exchange, :posts], page: @page, format: :json)
        )
      end
    end
  end

  def edit
    @exchange.body = @exchange.posts.first.body
    render template: "exchanges/edit"
  end

  def update
    @exchange.update(exchange_params.merge(updated_by: current_user))
    if @exchange.valid?
      flash[:notice] = "Your changes were saved."
      redirect_to @exchange
    else
      flash.now[:notice] = "Could not save your discussion! " \
                           "Please make sure all required fields are filled in."
      render template: "exchanges/edit"
    end
  end

  def mark_as_read
    mark_as_viewed!(
      @exchange,
      @exchange.posts.last,
      @exchange.posts_count
    )
    render layout: false, text: "OK" if request.xhr?
  end

  protected

  def context
    mobile_variant? ? 0 : 3
  end

  def mark_as_viewed!(exchange, last_post, count)
    return unless current_user?

    current_user.mark_exchange_viewed(exchange, last_post, count)
  end

  def verify_editable
    render_error 403 unless @exchange.editable_by?(current_user)
  end

  def search_query
    params[:query] || params[:q]
  end

  def require_and_set_search_query
    @search_query = search_query
    return if @search_query

    flash[:notice] = "No query specified!"
    redirect_to root_url
  end
end
