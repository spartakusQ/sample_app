require 'test_helper'
require 'minitest/color'

class StaticPagesControllerTest < ActionController::TestCase
  test "should get home" do
    get :home
    assert_response :success
    assert_select 'title', 'Home | Sample App'
  end

  test "should get help" do
    get :help
    assert_response :success
    assert_select 'title', 'Help | Sample App'
  end

  test 'should get about' do
    get :about
    assert_response :success
    assert_select 'title', 'About | Sample App'
  end

end
