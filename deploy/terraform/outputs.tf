output "cloudfront_domain" {
  value = aws_cloudfront_distribution.main.domain_name
}

output "web_bucket" {
  value = aws_s3_bucket.web.bucket
}

output "ecr_repository" {
  value = aws_ecr_repository.api.repository_url
}

output "audit_bucket" {
  value = aws_s3_bucket.audit.bucket
}
