
require 'json'
require 'aws-sdk'

# Used to perform cleanup on TA output
# To obtain the output from TA for seciurity groups
# 1, run the report in TA
# 2, obtain the check-id for the group report 'aws support describe-trusted-advisor-checks --language en'
# 3, get the output in json format  using the check-id '\
#    'aws support describe-trusted-advisor-check-result --language en --check-id 1iG5NDGVre --query 'result.sort_by
# (flaggedResources[?status!=`ok`],&metadata[2])[].metadata' --output json >> ~/Downloads/output.json
# https://docs.aws.amazon.com/sdkforruby/api/Aws/Support/Client.html#describe_trusted_advisor_checks-instance_method
class TrustedAdvisorCleaner
  def initialize(region)
    authenticate(region)
  end

  def authenticate(region)
    @region = region
    @my_credentials = Aws::Credentials.new(ENV['AWS_ACCESS_KEY_ID'],
                                           ENV['AWS_SECRET_ACCESS_KEY'],
                                           ENV['AWS_SESSION_TOKEN'])

    Aws.config.update(credentials: @my_credentials,
                      region: @region)
  end

  def load_json(file_location)
    file = File.read(file_location)
    # turn output from TA into hash
    create_result_hash(JSON.parse(file))
  end

  def create_result_hash(trusted_advisor_output)
    regions_found_in_hash = []
    @result = {}

    # get the regions from the trusted_advisor_output
    trusted_advisor_output.each do |e|
      regions_found_in_hash << e[0]
    end

    # Create a hash with each unique region and empty array.
    regions_found_in_hash.uniq.each do |e|
      @result[e] = []
    end

    # sort the orginal hash by region
    # access using @result['ap-southeast-1'] etc
    trusted_advisor_output.each do |e|
      @result.each do |key, _value|
        @result[key] << e if e[0] == key
      end
    end
  end

  def clean_groups
  end

  def retrieve_check_id(check_name)
    @support = Aws::Support::Client.new(
      region: 'us-east-1' # overide the region
    )
    response = @support.describe_trusted_advisor_checks(
      language: 'en', # required
    )
    # p response.successful?  <= true / false
    # p response.data.checks  <= array of checks

    if response.successful?
      # loop throught the checks array to find the security group one
      response.data.checks.each do |e|
        return e['id'] if e['name'] == check_name
      end
    end
  end

  def generate_output(check_name, output_file_name)
    # get the check-id
    check_id = retrieve_check_id(check_name)

    response = @support.describe_trusted_advisor_check_result(
      language: 'en',
      check_id: check_id
    )

    if response.successful?
      result = []
      response.data.result.flagged_resources.each do |e|
        result << e['metadata']
      end
      File.open(output_file_name, 'w') { |f| f.write JSON.pretty_generate(result) }
    end
  end

  def display_groups_in_output(display_type, input_file_name)
    load_json(input_file_name)
    region_only_array = []
    @result.each do |key, val|
      # only elements from the specific region
      region_only_array = val if key == @region
    end
    case display_type
    when 'array'
      # display all the elements
      region_only_array
    when 'groups_only'
      group_only_array = []
      region_only_array.each do |e|
        group_only_array << e[2].split[0]
      end
      group_only_array
    end
  end

  def remove_security_groups(file_name)
    groups = display_groups_in_output('groups_only', file_name)

    ec2 = Aws::EC2::Resource.new(
      region: @region # overide the region
    )
    p groups

    groups.each do |group|
      begin
        ec2.security_group(group).delete
        puts "#{group} deleted"
      rescue => e
        puts e.message
        next
      end
    end
  end

  def scrub_group(group_id)
    ec2 = Aws::EC2::Resource.new(
      region: @region # overide the region
    )

    ec2.security_group(group_id).ip_permissions.each do |permission|
      permission.ip_ranges.each do |ip_range|
        next unless ip_range['cidr_ip'] == '0.0.0.0/0'
        ec2.security_group(group_id).revoke_ingress(
          dry_run: false,
          ip_protocol: permission['ip_protocol'],
          cidr_ip: '0.0.0.0/0',
          from_port: permission['from_port'],
          to_port: permission['to_port']
          # source_security_group_name: ec2.security_group(group_id).group_name
          # # ip_permissions: permission
        )
      end
    end
  end

  def refresh_check(check_name)
    check_id = retrieve_check_id(check_name)

    response = @support.refresh_trusted_advisor_check(
      check_id: check_id
    )
    puts "check #{check_id} refreshed" if response.successful?
  end
end # end class

# security_group.revoke_ingress(IpProtocol="tcp", CidrIp="0.0.0.0/0", FromPort=3306, ToPort=3306)

filename = 'output-10.json'
TrustedAdvisorCleaner.new('ap-southeast-1').generate_output('Security Groups - Specific Ports Unrestricted', filename)
# p TrustedAdvisorCleaner.new('us-east-1').display_groups_in_output('array', filename)
# p TrustedAdvisorCleaner.new('eu-central-1').display_groups_in_output('groups_only', filename)
# TrustedAdvisorCleaner.new('ap-southeast-1').retrieve_check_id('Security Groups - Specific Ports Unrestricted')
# TrustedAdvisorCleaner.new('ap-southeast-1').refresh_check('Security Groups - Specific Ports Unrestricted')
# TrustedAdvisorCleaner.new('us-east-1').remove_security_groups(filename)
# p TrustedAdvisorCleaner.new('ap-southeast-1').scrub_group('sg-2ba95e4f')
