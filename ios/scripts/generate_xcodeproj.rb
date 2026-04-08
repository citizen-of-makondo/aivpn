#!/usr/bin/env ruby
# frozen_string_literal: true

require 'xcodeproj'
require 'pathname'

ROOT = Pathname.new(__dir__).parent
PROJECT_PATH = ROOT.join('AIVPN.xcodeproj')

PROJECT_PATH.rmtree if PROJECT_PATH.exist?
project = Xcodeproj::Project.new(PROJECT_PATH.to_s)

app_target = project.new_target(:application, 'AIVPN', :ios, '16.0')
tunnel_target = project.new_target(:app_extension, 'AIVPNTunnel', :ios, '16.0')
tests_target = project.new_target(:unit_test_bundle, 'AIVPNTests', :ios, '16.0')

def set_common_settings(target, bundle_id:, plist_path:, swift_version: '5.0')
  target.build_configurations.each do |config|
    config.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = bundle_id
    config.build_settings['INFOPLIST_FILE'] = plist_path
    config.build_settings['SWIFT_VERSION'] = swift_version
    config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '16.0'
    config.build_settings['CODE_SIGN_STYLE'] = 'Automatic'
    config.build_settings['GENERATE_INFOPLIST_FILE'] = 'YES'
    config.build_settings.delete('INFOPLIST_FILE')
  end
end

set_common_settings(app_target, bundle_id: 'com.aivpn.ios', plist_path: 'AIVPNApp/Info.plist')
set_common_settings(tunnel_target, bundle_id: 'com.aivpn.ios.tunnel', plist_path: 'AIVPNTunnel/Info.plist')
set_common_settings(tests_target, bundle_id: 'com.aivpn.ios.tests', plist_path: 'Tests/Info.plist')

# App-specific
app_target.build_configurations.each do |config|
  config.build_settings['PRODUCT_NAME'] = 'AIVPN'
  config.build_settings['TARGETED_DEVICE_FAMILY'] = '1,2'
end

# Tunnel-specific
tunnel_target.build_configurations.each do |config|
  config.build_settings['PRODUCT_NAME'] = 'AIVPNTunnel'
  config.build_settings['TARGETED_DEVICE_FAMILY'] = '1,2'
  config.build_settings['APPLICATION_EXTENSION_API_ONLY'] = 'YES'
  config.build_settings['LD_RUNPATH_SEARCH_PATHS'] = '$(inherited) @executable_path/Frameworks @executable_path/../../Frameworks'
end

tests_target.build_configurations.each do |config|
  config.build_settings['PRODUCT_NAME'] = 'AIVPNTests'
  config.build_settings['TEST_HOST'] = '$(BUILT_PRODUCTS_DIR)/AIVPN.app/AIVPN'
  config.build_settings['BUNDLE_LOADER'] = '$(TEST_HOST)'
end

main_group = project.main_group
app_group = main_group.new_group('AIVPNApp', 'AIVPNApp')
tunnel_group = main_group.new_group('AIVPNTunnel', 'AIVPNTunnel')
tests_group = main_group.new_group('Tests', 'Tests')

app_files = %w[AIVPNApp.swift ContentView.swift].map { |f| app_group.new_file(f) }
app_target.add_file_references(app_files)

tunnel_file = tunnel_group.new_file('PacketTunnelProvider.swift')
tunnel_target.add_file_references([tunnel_file])

test_file = tests_group.new_file('AIVPNTests.swift')
tests_target.add_file_references([test_file])

# Link test target with app target
tests_target.add_dependency(app_target)

# NetworkExtension framework for tunnel target
frameworks_group = project.frameworks_group
network_extension = frameworks_group.new_file('System/Library/Frameworks/NetworkExtension.framework')
tunnel_target.frameworks_build_phase.add_file_reference(network_extension)

# Embed extension into app
embed_phase = app_target.copy_files_build_phases.find { |p| p.name == 'Embed App Extensions' }
embed_phase ||= app_target.new_copy_files_build_phase('Embed App Extensions')
embed_phase.symbol_dst_subfolder_spec = :plug_ins
embed_phase.add_file_reference(tunnel_target.product_reference, true)

# App depends on tunnel build product for embedding
app_target.add_dependency(tunnel_target)

project.save
puts "Generated #{PROJECT_PATH}"
