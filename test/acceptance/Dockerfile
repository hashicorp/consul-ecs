# This Dockerfile installs all the dependencies necessary to run the unit and
# acceptance tests.
#
# This image has no automatic entrypoint. It is expected that you'll run
# a script to configure kubectl, potentially install Helm, and run the tests
# manually. This image only has the dependencies pre-installed.

FROM circleci/golang:1.14

# change the user to root so we can install stuff
USER root

ENV TERRAFORM_VERSION "0.14.6"

# base packages
RUN apt-get install -y \
    openssl \
    jq

# terraform
RUN curl -sSL https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip -o /tmp/tf.zip \
    && unzip /tmp/tf.zip  \
    && mv ./terraform /usr/local/bin/terraform

# AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install --bin-dir /usr/local/bin \
    && rm awscliv2.zip \
    && rm -rf ./aws

# AWS IAM authenticator
RUN curl -o aws-iam-authenticator https://amazon-eks.s3.us-west-2.amazonaws.com/1.18.9/2020-11-02/bin/linux/amd64/aws-iam-authenticator \
    && chmod +x ./aws-iam-authenticator \
    && mv ./aws-iam-authenticator /usr/local/bin/aws-iam-authenticator

# SSM Sessions Manager plugin for `aws ecs execute-command`
RUN curl -o session-manager-plugin.deb https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb \
   && sudo dpkg -i session-manager-plugin.deb \
   && rm session-manager-plugin.deb

# change the user back to what circleci/golang image has
USER circleci
