# frozen_string_literal: true

class AddStatusToUsers < ActiveRecord::Migration[5.2]
  def up
    add_column :users, :status, :integer, null: false, default: 0

    User.where.not(banned_until: nil).each { |u| u.update(status: :hiatus) }
    User.where(banned: true).each { |u| u.update(status: :banned) }
    User.where(memorialized: true).each { |u| u.update(status: :memorialized) }

    change_table(:users, bulk: true) do |t|
      t.remove :memorialized
      t.remove :banned
    end
  end

  def down
    change_table(:users, bulk: true) do |t|
      t.boolean :banned, null: false, default: false
      t.boolean :memorialized, null: false, default: false
    end
    User.reset_column_information

    User.all.each do |user|
      case user.status
      when :memorialized
        user.update(memorialized: true)
      when :banned, :inactive
        user.update(banned: true)
      end
    end

    remove_column :users, :status
  end
end
