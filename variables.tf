variable "aws_region" {
}
variable "aws_profile" {
}
variable "name_prefix" {
}
variable "vpc_cidr_block" {
  # default = "10.0.0.0/16"
}
variable "my_ip" {
  default = "73.142.34.8/32"
}
variable "security_cidr" {
  default = "0.0.0.0/0"
}
variable "ami_id" {
  default = "ami-0e1b10c04f850acd7"
}
variable "instance_type" {
  default = "t2.micro"
}
variable "key_name" {
  default = "ec2"
}
variable "db_username" {
  default = "csye6225"
}
variable "db_password" {
}
variable "db_name" {
  default = "csye6225"
}
variable "db_identifier" {
  default = "csye6225"
}
variable "db_port" {
  default = 5432
}
variable "db_instance_class" {
  default = "db.t3.micro"
}
variable "db_version" {
  default = "11"
}
variable "db_engine" {
  default = "postgres"
}
variable "db_storage" {
  default = 10
}
variable "domain_name" {
  default = "dev.ganeshvasa.me"
}

variable "cpu_upper_limit" {
  default = "5"
}

variable "cpu_lower_limit" {
  default = "3"
}

variable "account_id" {
  default = "287953200237"
}