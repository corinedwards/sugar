# frozen_string_literal: true

require "rails_helper"

describe Configuration, redis: true do
  let(:configuration) { described_class.new }

  describe ".settings" do
    subject { described_class.settings }

    it { is_expected.to be_a(Hash) }
  end

  describe ".setting" do
    before do
      described_class.class_eval do
        setting :foo, :string
      end
    end

    it "defaults to nil" do
      expect(configuration.foo).to be_nil
    end

    it "defines a reader" do
      configuration.foo("baz")
      expect(configuration.foo).to eq("baz")
    end

    it "defines a boolean reader" do
      expect(configuration.foo?).to be(false)
    end

    it "defines a writer" do
      configuration.foo = "bar"
      expect(configuration.foo).to eq("bar")
    end
  end

  describe "#get" do
    subject { configuration.get(setting) }

    let(:setting) { :forum_name }

    it { is_expected.to eq("Sugar") }

    it "raises an error when setting doesn't exist" do
      expect { configuration.get(:inexistant) }.to(
        raise_error(Configuration::InvalidConfigurationKey)
      )
    end
  end

  describe "#set" do
    subject { configuration.set(setting, value) }

    let(:setting) { :forum_name }
    let(:value) { "Foo" }

    it { is_expected.to eq("Foo") }

    it "raises an error when setting doesn't exist" do
      expect { configuration.set(:inexistant, "Foo") }.to(
        raise_error(Configuration::InvalidConfigurationKey)
      )
    end

    it "raises an error when value is an invalid type" do
      expect { configuration.set(:forum_name, 1.0) }.to(
        raise_error(ArgumentError)
      )
    end
  end

  describe "#load" do
    let(:other_configuration) { described_class.new }

    before do
      other_configuration.update(forum_name: "Test")
    end

    it "loads the configuration from Redis" do
      expect { configuration.load }.to(
        change(configuration, :forum_name).from("Sugar").to("Test")
      )
    end
  end

  describe "#save" do
    let(:other_configuration) { described_class.new }

    before do
      configuration.forum_name = "Save test"
      configuration.save
    end

    it "saves the configuration to Redis" do
      expect { other_configuration.load }.to(
        change(other_configuration, :forum_name).from("Sugar").to("Save test")
      )
    end
  end

  describe "#update" do
    let(:other_configuration) { described_class.new }

    before { configuration.update(forum_name: "Update test") }

    it "updates the configuration" do
      expect { other_configuration.load }.to(
        change(other_configuration, :forum_name).from("Sugar").to("Update test")
      )
    end
  end

  describe "#reset!" do
    before { configuration.forum_name = "Reset test" }

    it "resets the configuration" do
      expect { configuration.reset! }.to(
        change(configuration, :forum_name).from("Reset test").to("Sugar")
      )
    end
  end
end
