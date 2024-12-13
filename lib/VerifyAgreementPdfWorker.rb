class VerifyAgreementPdfWorker
  include Sidekiq::Worker

  sidekiq_options retry: false

  def perform(agreement_id)
    agreement = Agreement.find(agreement_id)
    puts "Verifying PDF for Agreement ID: #{agreement.id}"

    certificate = agreement.certificate
    puts "Loaded certificate for Agreement ID: #{agreement.id}: #{certificate.inspect}"

    pdf_content = agreement.pdf_file.download
    puts "Downloaded PDF content for Agreement ID: #{agreement.id}"

    verifier = PdfVerifier.new(pdf_content, certificate)
    if verifier.verify
      puts "✅ PDF for Agreement ID: #{agreement.id} is valid and has not been manipulated."
    else
      puts "❌ PDF for Agreement ID: #{agreement.id} has been manipulated or is invalid."
    end
    
  rescue ActiveRecord::RecordNotFound
    puts "❌ Agreement with ID #{agreement_id} not found."
  rescue => e
    puts "❌ An error occurred during PDF verification: #{e.message}"
    puts e.backtrace
  end
end 