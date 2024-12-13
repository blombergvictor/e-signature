require "hexapdf"
require "openssl"
require "base64"
require "stringio"

class PdfVerifier
  def initialize(pdf_content, certificate)
    @pdf_content = pdf_content
    @certificate = certificate
    puts "Initialized PdfVerifier with certificate: #{@certificate.inspect}"
  end

  def verify
    puts "Starting verification process..."

    doc = HexaPDF::Document.new(io: StringIO.new(@pdf_content))
    puts "Loaded PDF document for verification."

    # Extract metadata from PDF
    signature = doc.trailer.info[:SmartSignature]
    stored_hash = doc.trailer.info[:SmartHash]
    certificate_serial = doc.trailer.info[:SmartCertificateSerial]
    issuer = doc.trailer.info[:SmartIssuer]

    puts "Extracted metadata from PDF:"
    puts "SmartSignature: #{signature}"
    puts "SmartHash: #{stored_hash}"
    puts "SmartCertificateSerial: #{certificate_serial}"
    puts "SmartIssuer: #{issuer}"

    # Remove SmartSignature and dynamic fields before recomputing the hash
    doc.trailer.info.delete(:SmartSignature)
    doc.trailer.info[:ModDate] = 'D:20200101000000+00\'00\''
    doc.trailer.info[:CreationDate] = 'D:20200101000000+00\'00\''
    doc.trailer.info.delete(:SmartSignedAt)

    output = StringIO.new
    doc.write(output, validate: false, optimize: false)
    pdf_without_signature = output.string

    # Compute the hash over the PDF content without SmartSignature and dynamic fields
    pdf_hash = Digest::SHA256.hexdigest(pdf_without_signature)
    puts "Recomputed hash during verification: #{pdf_hash}"

    # Verify signature
    is_signature_valid = verify_signature(signature, pdf_hash)
    if is_signature_valid
      puts "✅ Signature verification passed"
    else
      puts "❌ Signature verification failed"
    end

    # Compare stored hash with recomputed hash
    is_hash_valid = stored_hash == pdf_hash
    if is_hash_valid
      puts "✅ Hash verification passed"
    else
      puts "❌ Hash verification failed"
    end

    is_signature_valid && is_hash_valid
  
  rescue => e
    puts "❌ An error occurred during PDF verification: #{e.message}"
    puts e.backtrace
    false
  end

  private

  def verify_signature(signature, data)
    return false unless signature && data && @certificate

    public_key = OpenSSL::PKey::RSA.new(@certificate.public_key)
    decoded_signature = Base64.strict_decode64(signature)
    puts "Decoded signature: #{decoded_signature}"

    puts "Encoded signature: #{Base64.strict_encode64(decoded_signature)}"

    public_key.verify(OpenSSL::Digest::SHA256.new, decoded_signature, data)
  end
end