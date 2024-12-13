class AgreementCertificateService
  include SerialNumberGenerator

  def initialize(agreement)
    @agreement = agreement
  end

  def generate_certificate
    return unless certificate_should_be_generated?

    key_pair = CryptographyService.generate_key_pair

    Certificate.transaction do
      certificate = create_certificate(key_pair[:public_key])
      store_private_key(certificate, key_pair[:private_key])
      @agreement.update!(certificate: certificate)
    end

  rescue ActiveRecord::RecordInvalid => e
    handle_error(e, "Misslyckades med att generera certifikat för avtal")
  rescue StandardError => e
    handle_error(e, "Ett oväntat fel inträffade vid generering av certifikat")
  end

  private

  def certificate_should_be_generated?
    @agreement.status == "sent"
  end

  def create_certificate(public_key)
    revoke_existing_certificate if active_certificate_exists?

    Certificate.create!(
      certifiable: @agreement,
      issued_by_team_member: @agreement.issued_by_team_member,
      certificate_holder_name: @agreement.company_name,
      certificate_holder_email: @agreement.company_email,
      certificate_holder_organization_number: @agreement.company_organization_number,
      key_usage: "agreement_certification",
      public_key: public_key,
      public_key_algorithm: "RSA",
      signature_algorithm: "SHA256withRSA",
      serial_number: generate_serial_number,
      valid_from_date: Time.current,
      valid_to_date: 1.year.from_now,
      status: "active"
    )
  end

  def store_private_key(certificate, private_key)
    encrypted_key = encrypt_private_key(private_key)
    certificate.update!(encrypted_private_key: encrypted_key)
  end

  def encrypt_private_key(private_key)
    kms_client = initialize_kms_client
    response = kms_client.encrypt(
      key_id: construct_key_arn,
      plaintext: private_key
    )
    Base64.strict_encode64(response.ciphertext_blob)
  
  rescue Aws::KMS::Errors::NotFoundException => e
    handle_error(e, "KMS-nyckel hittades inte")
  
  rescue StandardError => e
    handle_error(e, "Ett fel inträffade vid kryptering av privat nyckel")
  end

  def initialize_kms_client
    Aws::KMS::Client.new(
      region: aws_credentials[:kms_region],
      credentials: Aws::Credentials.new(
        aws_credentials[:access_key_id],
        aws_credentials[:secret_access_key]
      )
    )
  end

  def construct_key_arn
    "arn:aws:kms:#{aws_credentials[:kms_region]}:" \
    "#{aws_credentials[:account_id]}:" \
    "key/#{aws_credentials[:kms_key_id]}"
  end

  def aws_credentials
    @aws_credentials ||= Rails.application.credentials.dig(Rails.env.to_sym, :amazon)
  end

  def active_certificate_exists?
    @agreement.certificate&.status == "active"
  end

  def revoke_existing_certificate
    existing_certificate = @agreement.certificate
    existing_certificate.revoke!("Ersatt av nytt certifikat") if existing_certificate
  end

  def handle_error(error, message)
    ErrorHandlingService.new(
      error: error,
      context: { agreement_id: @agreement.id },
      send_email_with_event: true
    ).handle_error
    raise "#{message}: #{error.message}"
  end
end