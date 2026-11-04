variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "domain" {
  type    = string
  default = "vault.arevei.com"
}

variable "api_image_tag" {
  type        = string
  description = "Immutable ECR tag of the server image (git SHA)."
}

variable "api_count" {
  type    = number
  default = 2
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.small"
}

variable "alb_certificate_arn" {
  type        = string
  description = "ACM certificate in var.region for the ALB origin."
}

variable "cloudfront_certificate_arn" {
  type        = string
  description = "ACM certificate in us-east-1 for var.domain."
}
