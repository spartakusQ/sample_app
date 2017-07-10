class User < ActiveRecord::Base
  attr_accessor :remember_token, :activation_token
  before_save :downcase_email
  before_create :create_activation_digest
  validates :name, presence: true
  validates :email, presence: true
  before_save { self.email = email.downcase }
  validates :name, presence: true, length: { maximum: 50 }
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates :email, presence: true, length: { maximum: 255 },
                                    format: { with: VALID_EMAIL_REGEX },
                                    uniqueness: { case_sensitive: false }
  has_secure_password
  validates :password, length: { minimum: 6 }, allow_blank: true

  def User.digest(string) cost = ActiveModel::SecurePassword.min_cost ?
    BCrypt::Engine::MIN_COST :
    BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end
  # Токен безопасности.
  def User.new_token
    SecureRandom.urlsafe_base64
  end
  # Сохранение пользователя в бд для сеансов.
  def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end
  # Возвращает true, если указанный токен соответствует дайджесту.
  def authenticated?(remember_token)
    return false if remember_digest.nil?
    BCrypt::Password.new(remember_digest).is_password?(remember_token)
  end
  # Забывает пользователя
  def forget
     update_attribute(:remember_digest, nil)
  end

  private
  # Преобразует адрес электронной почты в нижний регистр.
  def downcase_email
    self.email = email.downcase 
  end
  # Создает и присваивает токен активации и его дайджест.
  def create_activation_digest
    self.activation_token = User.new_token
    self.activation_digest = User.digest(activation_token)
  end
end
