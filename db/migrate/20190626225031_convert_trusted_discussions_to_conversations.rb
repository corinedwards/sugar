# frozen_string_literal: true

class ConvertTrustedDiscussionsToConversations < ActiveRecord::Migration[5.2]
  def up
    trusted_users = User.active_and_memorialized.where(
      "trusted = ? OR admin = ? OR user_admin = ? OR moderator = ?",
      true,
      true,
      true,
      true
    )

    Discussion.where(trusted: true).each do |d|
      raise Discussion::InvalidExchange unless d.valid?

      d.update(type: "Conversation")
      d.becomes(Conversation).tap do |conversation|
        conversation.unlabel!
        d.posts.each { |p| p.update(conversation: true) }
        trusted_users.each do |p|
          conversation.add_participant(p, new_posts: false)
        end
        d.discussion_relationships.destroy_all
      end
    end
  end

  def down
    Conversation.where(trusted: true).each do |c|
      raise Discussion::InvalidExchange unless c.valid?

      c.update(type: "Discussion")
      c.becomes(Conversation).tap do |discussion|
        d.posts.each { |p| p.update(conversation: false) }
        c.participants.each do |p|
          DiscussionRelationship.define(p, discussion, participated: true)
        end
        c.conversation_relationships.destroy_all
      end
    end
  end
end
