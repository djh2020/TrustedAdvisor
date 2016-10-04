# Rakefile

# --fail-level E will only fail Ruby errors.
# The warnings scan will still count and graph [W]arning and [C]op violations.
desc 'Rubocop linting task'
task :rubocop do
  sh 'rubocop --fail-level E' do |ok|
    sh 'exit 1' unless ok
  end
end

desc 'Install required gems...'
task :install_gems do
  sh 'bundle install' do |ok|
    sh 'exit 1' unless ok
  end
end
