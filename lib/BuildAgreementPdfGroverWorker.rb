class BuildAgreementPdfGroverWorker
  include Sidekiq::Worker
  include Rails.application.routes.url_helpers

  sidekiq_options queue: 'pdf_generation', retry: 10

  MAX_RETRY_ATTEMPTS = 20
  RETRY_DELAY_SECONDS = 15

  def perform(agreement_id, attempt_number = 1)
    @agreement = Agreement.find(agreement_id)
    puts "Processing Agreement ID: #{@agreement.id}"
    
    if @agreement.accepted? && @agreement.pdf_url.present?
      puts "PDF already exists, skipping generation, #{@agreement.pdf_url}"
      return
    end

    puts "--------------------------------"
    puts "Attempt #{attempt_number}"
    
    host = determine_host
    url = generate_document_url(@agreement, host)
    puts "Generated URL for PDF: #{url}"

    pdf = generate_pdf(url)
    puts "Generated PDF for Agreement ID: #{@agreement.id}"

    secured_pdf = add_metadata(pdf)
    puts "Added metadata to PDF for Agreement ID: #{@agreement.id}"

    attach_pdf_to_agreement(@agreement, secured_pdf)
    puts "Attached secured PDF to Agreement ID: #{@agreement.id}"
    
    # Confirm that the PDF is attached before updating
    if @agreement.pdf_file.attached?
      @agreement.update!(
        pdf_file_created_at: Time.current
      )

      log_attachment_status(@agreement, host, secured_pdf)
    elsif attempt_number < MAX_RETRY_ATTEMPTS
      puts "Attempt #{attempt_number}: Failed to attach PDF to Agreement ##{@agreement.id}. Retrying in #{RETRY_DELAY_SECONDS} seconds..."
      self.class.perform_in(RETRY_DELAY_SECONDS, agreement_id, attempt_number + 1)
    else
      puts "PDF not attached after #{MAX_RETRY_ATTEMPTS} attempts for Agreement ##{@agreement.id}. Giving up."
    end
  end

  private

  def determine_host
    Rails.env.production? ? "https://app.smartproduktion.se" : "http://localhost:3000"
  end

  def generate_document_url(agreement, host)
    document_as_creator_url(
      agreement.uuid,
      host: host,
      from: 'worker',
      preview: true,
      hideForPdf: true
    )
  end

  def generate_pdf_hash(pdf_content)
    Digest::SHA256.hexdigest(pdf_content)
  end

  def sign_pdf_hash(pdf_hash)
    return nil unless @agreement.certificate&.encrypted_private_key

    # Decrypt the private key using AWS KMS
    kms_client = Aws::KMS::Client.new(
      region: Rails.application.credentials.dig(Rails.env.to_sym, :amazon, :kms_region),
      credentials: Aws::Credentials.new(
        Rails.application.credentials.dig(Rails.env.to_sym, :amazon, :access_key_id),
        Rails.application.credentials.dig(Rails.env.to_sym, :amazon, :secret_access_key)
      )
    )

    # Decode the encrypted private key
    encrypted_key = Base64.strict_decode64(@agreement.certificate.encrypted_private_key)
    
    # Decrypt using KMS
    decrypted_result = kms_client.decrypt(ciphertext_blob: encrypted_key)
    private_key = OpenSSL::PKey::RSA.new(decrypted_result.plaintext)
    
    # Sign the hash with the private key
    signature = private_key.sign(OpenSSL::Digest::SHA256.new, pdf_hash)
    
    Base64.strict_encode64(signature)
  end

  def add_metadata(pdf)
    require 'hexapdf'

    doc = HexaPDF::Document.new(io: StringIO.new(pdf))

    # Add metadata excluding SmartSignature and dynamic fields
    doc.trailer.info[:ModDate] = 'D:20200101000000+00\'00\''
    doc.trailer.info[:CreationDate] = 'D:20200101000000+00\'00\''
    doc.trailer.info[:SmartCertificateSerial] = @agreement.certificate.serial_number
    doc.trailer.info[:SmartIssuer] = @agreement.certificate.issuer_details.encode('UTF-8')

    # Serialize without SmartSignature and dynamic fields
    output = StringIO.new
    doc.write(output, validate: false, optimize: false)
    pdf_with_metadata = output.string

    # Compute hash over PDF content with metadata (excluding SmartSignature)
    pdf_hash = Digest::SHA256.hexdigest(pdf_with_metadata)
    puts "Computed pdf_hash during signing (after adding metadata): #{pdf_hash}"

    # Sign the hash
    signature = sign_pdf_hash(pdf_hash)
    puts "Generated signature for Agreement ID: #{@agreement.id}"

    # Now add the SmartHash, SmartSignature, and dynamic fields
    doc.trailer.info[:SmartHash] = pdf_hash
    doc.trailer.info[:SmartSignature] = signature
    doc.trailer.info[:SmartSignedAt] = Time.current.utc.iso8601(0)

    final_output = StringIO.new
    doc.write(final_output, validate: false, optimize: false)
    final_output.string
  end

  def generate_pdf(url)
    require 'grover'
    
    # Configure Grover with metadata support
    Grover.new(
      url,
      format: 'A4',
      margin: {
        top: '1cm',
        bottom: '1cm',
        left: '0.5cm',
        right: '0.5cm'
      },
      wait_until: 'networkidle0',
      extra: {
        'waitForFunction' => 'window.setTimeout(() => true, 5000)' # Wait for 5 seconds
      },
      display_header_footer: true,
      footer_template: footer_template, 
      header_template: header_template
    ).to_pdf
  end

  def attach_pdf_to_agreement(agreement, pdf)
    agreement.pdf_file.attach(
      io: StringIO.new(pdf),
      filename: "agreement_#{agreement.uuid}.pdf",
      content_type: 'application/pdf'
    )
  end

  def log_attachment_status(agreement, host, secured_pdf)
    if agreement.pdf_file.attached?
      pdf_url = rails_blob_url(agreement.pdf_file, host: host)
      puts "PDF attached at URL: #{pdf_url}"
      
      # Log the metadata trailer for debugging
      doc = HexaPDF::Document.new(io: StringIO.new(secured_pdf))
      puts "PDF Metadata Trailer: #{doc.trailer.info.inspect}"
    else
      puts "PDF attachment failed for agreement #{agreement.id}"
    end
  end

  def header_template
    <<~HTML
      <div class="PDF" style="font-size: 10px; width: 100%; padding: 0 0.5cm; display: flex; justify-content: space-between; font-family: 'Arial';">
      </div>
    HTML
  end
  
  def fingerprint_template
    <<~HTML
      <div class="PDF" style="color: #666; font-family: 'Arial';">
        Certifikat: #{@agreement&.certificate&.serial_number}
      </div>
    HTML
  end

  def footer_template
    <<~HTML
      <div class="PDF" style="font-size: 10px; width: 100%; padding: 0 0.5cm; display: flex; justify-content: space-between; font-family: 'Arial';">
        #{@agreement&.certificate&.serial_number ? fingerprint_template : ''}

        <div style="color: #666; font-family: 'Arial';">
          <span class="pageNumber"></span> / <span class="totalPages"></span>
        </div>
      </div>
    HTML
  end
end