# VPC
resource "aws_vpc" "vpc" {
  cidr_block = var.vpc_cidr_block

  tags = {
    Name = "my-${var.name_prefix}-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "my-igw"
  }
}

# Public subnets
resource "aws_subnet" "public" {
  count = 3

  cidr_block        = cidrsubnet(var.vpc_cidr_block, 8, count.index)
  vpc_id            = aws_vpc.vpc.id
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "my-${var.name_prefix}-public-subnet-${count.index + 1}"
  }
}

resource "aws_db_subnet_group" "private_group" {
  name       = "private_group"
  subnet_ids = [aws_subnet.private[0].id, aws_subnet.private[1].id, aws_subnet.private[2].id]

  tags = {
    Name = "Private subnet group"
  }
}

# Private subnets
resource "aws_subnet" "private" {
  count = 3

  cidr_block        = cidrsubnet(var.vpc_cidr_block, 8, count.index + 11)
  vpc_id            = aws_vpc.vpc.id
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "my-${var.name_prefix}-private-subnet-${count.index + 1}"
  }
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "my-${var.name_prefix}-public-rt"
  }
}

# Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "my-${var.name_prefix}-private-rt"
  }
}

# Associate Public Subnets with Public Route Table
resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Associate Private Subnets with Private Route Table
resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "application" {
  name        = "application"
  description = "Security group for the Webapp application"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer.id]
  }
  ingress {
    from_port       = 9234
    to_port         = 9234
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.security_cidr]
  }

  tags = {
    Name = "application"
  }
}

resource "aws_security_group" "database" {
  name        = "database"
  description = "Security group for the database"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.security_cidr]
  }

  tags = {
    Name = "database"
  }
}

resource "random_pet" "rg" {
  keepers = {
    # Generate a new pet name each time we switch to a new profile
    random_name = var.aws_profile
  }
}


resource "aws_s3_bucket" "s3b" {
  bucket        = random_pet.rg.id
  force_destroy = true
  tags = {
    Name = "${random_pet.rg.id}"
  }
}
resource "aws_s3_bucket_acl" "s3b_acl" {
  bucket = aws_s3_bucket.s3b.id
  acl    = "private"
}
resource "aws_s3_bucket_lifecycle_configuration" "s3b_lifecycle" {
  bucket = aws_s3_bucket.s3b.id
  rule {
    id     = "rule-1"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3b_encryption" {
  bucket = aws_s3_bucket.s3b.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }

}
resource "aws_s3_bucket_public_access_block" "s3_block" {
  bucket                  = aws_s3_bucket.s3b.id
  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_db_parameter_group" "postgres_11" {
  name   = "rds-pg-${var.name_prefix}"
  family = "postgres${var.db_version}"
  parameter {
    apply_method = "immediate"
    name         = "lc_messages"
    value        = "en_US.UTF-8"
  }
  parameter {
    apply_method = "immediate"
    name         = "lc_monetary"
    value        = "en_US.UTF-8"
  }
  parameter {
    apply_method = "immediate"
    name         = "lc_numeric"
    value        = "en_US.UTF-8"
  }
  parameter {
    apply_method = "immediate"
    name         = "lc_time"
    value        = "en_US.UTF-8"
  }
  parameter {
    apply_method = "immediate"
    name         = "autovacuum"
    value        = "1"
  }

}

resource "aws_iam_policy" "policy" {
  name        = "WebAppS3"
  description = "policy for s3"

  policy = jsonencode({
    "Version" : "2012-10-17"
    "Statement" : [
      {
        "Action" : ["s3:DeleteObject", "s3:PutObject", "s3:GetObject", "s3:ListAllMyBuckets"]
        "Effect" : "Allow"
        "Resource" : ["arn:aws:s3:::${aws_s3_bucket.s3b.bucket}", "arn:aws:s3:::${aws_s3_bucket.s3b.bucket}/*"]
      }
    ]
  })
}

resource "aws_iam_role" "ec2_role" {
  name = "EC2-CSYE6225"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "webapps3_policy_attachment" {
  policy_arn = aws_iam_policy.policy.arn
  role       = aws_iam_role.ec2_role.name
}

resource "aws_iam_policy_attachment" "webapp_cloudwatch_policy_attachment" {
  name       = "webapp_cloudwatch_policy_attachment"
  roles      = [aws_iam_role.ec2_role.name]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_security_group" "load_balancer" {
  name        = "load_balancer"
  description = "Security group for the load balancer"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.security_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.security_cidr]
  }

  tags = {
    Name = "load balancer"
  }
}


resource "aws_kms_key" "rds_kmskey" {
  description             = "rds key"
  deletion_window_in_days = 10
  policy = jsonencode({
    Id = "key-consolepolicy-1"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions",
        Effect = "Allow",
        Principal = {
          "AWS" : "arn:aws:iam::287953200237:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "Allow use of the key",
        Effect = "Allow",
        Principal = {
          "AWS" : "arn:aws:iam::287953200237:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      },
      {
        Sid    = "Allow attachment of persistent resources",
        Effect = "Allow",
        Principal = {
          "AWS" : "arn:aws:iam::287953200237:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ],
        Resource = "*",
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" : "true"
          }
        }
      }
    ]
    Version = "2012-10-17"
  })
}


resource "aws_db_instance" "mydb" {
  allocated_storage      = var.db_storage
  engine                 = var.db_engine
  engine_version         = var.db_version
  instance_class         = var.db_instance_class
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.rds_kmskey.arn
  multi_az               = false
  identifier             = var.db_identifier
  username               = var.db_username
  password               = var.db_password
  db_name                = var.db_name
  port                   = var.db_port
  publicly_accessible    = false
  skip_final_snapshot    = true
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  db_subnet_group_name   = aws_db_subnet_group.private_group.name
  parameter_group_name   = aws_db_parameter_group.postgres_11.name
}

resource "aws_iam_instance_profile" "iam_profile" {
  name = "iam_profile"
  role = aws_iam_role.ec2_role.name
}

data "template_file" "user_data" {

  template = <<EOF
#!/bin/bash
sudo cp /tmp/cloudwatchagent_config.json /opt/cloudwatchagent_config.json
sudo chmod 774 /opt/cloudwatchagent_config.json
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/cloudwatchagent_config.json -s

cd /home/ec2-user || return
touch custom.properties
echo "aws.region=${var.aws_region}" >> custom.properties
echo "aws.s3.bucket=${aws_s3_bucket.s3b.bucket}" >> custom.properties

echo "spring.datasource.driver-class-name=org.postgresql.Driver" >> custom.properties
echo "spring.datasource.url=jdbc:postgresql://${aws_db_instance.mydb.endpoint}/${aws_db_instance.mydb.db_name}?useSSL=true&requireSSL=true" >> custom.properties
echo "spring.datasource.username=${aws_db_instance.mydb.username}" >> custom.properties
echo "spring.datasource.password=${aws_db_instance.mydb.password}" >> custom.properties

echo "spring.datasource.dbcp2.test-while-idle=true" >> custom.properties
echo "spring.jpa.hibernate.ddl-auto=update" >> custom.properties
echo "spring.main.allow-circular-references=true" >> custom.properties
echo "server.port=9234" >> custom.properties
echo "logging.file.path=/home/ec2-user" >> custom.properties
echo "logging.file.name=/home/ec2-user/csye6225logs.log" >> custom.properties
echo "publish.metrics=true" >> custom.properties
echo "metrics.statsd.host=localhost" >> custom.properties
echo "metrics.statsd.port=8125" >> custom.properties
echo "metrics.prefix=webapp" >> custom.properties
  EOF

}


resource "aws_kms_key" "ec2_ebs_key" {
  description             = "ebs key"
  deletion_window_in_days = 10
  policy = jsonencode({
    Id = "key-consolepolicy-1"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions",
        Effect = "Allow",
        Principal = {
          "AWS" : "arn:aws:iam::287953200237:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "Allow use of the key",
        Effect = "Allow",
        Principal = {
          "AWS" : "arn:aws:iam::287953200237:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      },
      {
        Sid    = "Allow attachment of persistent resources",
        Effect = "Allow",
        Principal = {
          "AWS" : "arn:aws:iam::287953200237:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ],
        Resource = "*",
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" : "true"
          }
        }
      }
    ]
    Version = "2012-10-17"
  })
}



resource "aws_launch_template" "asg_launch_config" {
  name = "asg_launch_config"
  block_device_mappings {
    device_name = "/dev/sdf"
    ebs {
      delete_on_termination = true
      volume_size           = 50
      volume_type           = "gp2"
      encrypted             = true
      kms_key_id            = aws_kms_key.ec2_ebs_key.arn
    }
  }
  disable_api_termination = false
  iam_instance_profile {
    name = aws_iam_instance_profile.iam_profile.name
  }
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name
  monitoring {
    enabled = true
  }
  network_interfaces {
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.public[1].id
    security_groups             = [aws_security_group.application.id]
  }
  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "asg_launch_config"
    }
  }
  user_data = base64encode(data.template_file.user_data.rendered)

}

resource "aws_autoscaling_group" "autoscaling_group" {
  name                = "autoscaling_group"
  desired_capacity    = 1
  max_size            = 3
  min_size            = 1
  default_cooldown    = 60
  vpc_zone_identifier = [for k, v in aws_subnet.public : v.id]
  target_group_arns   = [aws_lb_target_group.alb_tg.arn]

  tag {
    key                 = "Application"
    value               = "WebApp"
    propagate_at_launch = true
  }

  launch_template {
    id      = aws_launch_template.asg_launch_config.id
    version = "$Latest"
  }
}
resource "aws_autoscaling_policy" "scale_up" {
  name                   = "scale_up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 10
  autoscaling_group_name = aws_autoscaling_group.autoscaling_group.name
}

resource "aws_cloudwatch_metric_alarm" "upper_limit" {
  alarm_name          = "upper_limit"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = var.cpu_upper_limit

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.autoscaling_group.name
  }

  alarm_description = "Checks if the ec2 instance crosses the defined upper limit and triggers a scale up policy"
  alarm_actions     = [aws_autoscaling_policy.scale_up.arn]
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "scale_down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 10
  autoscaling_group_name = aws_autoscaling_group.autoscaling_group.name
}

resource "aws_cloudwatch_metric_alarm" "lower_limit" {
  alarm_name          = "lower_limit"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = var.cpu_lower_limit

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.autoscaling_group.name
  }

  alarm_description = "Checks if the ec2 instance falls below the defined lower limit and triggers a scale down policy"
  alarm_actions     = [aws_autoscaling_policy.scale_down.arn]
}

resource "aws_lb" "lb" {
  name               = "webapp-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer.id]
  subnets            = [for subnet in aws_subnet.public : subnet.id]

  enable_deletion_protection = false

  tags = {
    application = "WebApp"
  }
}

resource "aws_lb_target_group" "alb_tg" {
  name        = "alb-tg"
  target_type = "instance"
  port        = 9234
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc.id
  health_check {
    path                = "/healthz"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 15
    matcher             = "200"
  }
}

resource "aws_lb_listener" "lb_listener" {
  load_balancer_arn = aws_lb.lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:287953200237:certificate/3d64e5e3-58fe-4421-a54a-4ffb3b13f97c"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb_tg.arn
  }
}
data "aws_route53_zone" "zone_data" {
  name = var.domain_name
}

resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.zone_data.zone_id
  name    = data.aws_route53_zone.zone_data.name
  type    = "A"
  alias {
    name                   = aws_lb.lb.dns_name
    zone_id                = aws_lb.lb.zone_id
    evaluate_target_health = true
  }
}

# Data Sources
data "aws_availability_zones" "available" {}

