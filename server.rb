require 'json'
require 'webrick'

def extract_httpx(line)
  {
    url: line['url'],
    status: line['status_code'],
    size: line['content_length'],
    title: line['title'],
    ip: line['a'],
    cname: line['cname'],
    cdn: line['cdn'],
    tech: line['tech'],
    headers: line['header']
  }
end

def handler(domain)
  file_name = "#{(0...10).map { ('a'..'z').to_a[rand(26)] }.join}.json"

  cmd = "subfinder -pc /app/subfinder.yaml -silent -d #{domain} |"
  cmd += "puredns resolve -q --resolvers resolvers.txt --resolvers-trusted resolvers-trusted.txt |"
  cmd += "httpx -silent -sc -cl -title -td -ip -cname -cdn -irh -j -o #{file_name}"

  system(cmd, %i[out err] => File::NULL)

  json_array = []
  File.readlines(file_name).each do |line|
  	line = JSON.parse(line)
  	json_array << extract_httpx(line)
  end
  File.delete(file_name) if File.exist?(file_name)

  json_array.to_json
end

server = WEBrick::HTTPServer.new(:Port => 8080)
server.mount_proc("/") do |request, response|
  domain = request.request_uri.path.delete_prefix("/")

  if domain.empty?
    response.status = 400
    response.body = "Error: domain is required"
  else
    response.status = 200
    response.header['Content-Type'] = 'application/json'
    response.body = handler(domain)
  end
end

trap("INT") { server.shutdown }
server.start