#!/usr/bin/ruby
require 'net/http'
require 'digest'
require 'uri'
require 'openssl'
require 'base64'
require 'digest/md5'
require 'rexml/document'

class Create_Header
    def initialize(access_key, secret_key)
        @access_key = access_key
        @secret_key = secret_key
    end
    def  create_sign_str(http_method,url,content_md5,content_type,params,canonicalized_amz_headers=nil)
        http_header_date = (Time.new - 8*3600).strftime('%a, %d %b %Y %H:%M:%S GMT')
        sign_param_list =  Array[ http_method, content_md5, content_type, http_header_date ]
        if canonicalized_amz_headers != ""
            sign_param_list << canonicalized_amz_headers
        end
        sign_param_list << url
        return sign_param_list.join("\n")
    end
    def create_sign(method, path, params)
        canonicalized_amz_headers = ""
        if params.key?('x-amz-acl')
            canonicalized_amz_headers = "x-amz-acl:%s" % "#{params['x-amz-acl']}"
        end
        sign_str = create_sign_str(
                http_method=method,
                url=path,
                content_md5="#{params['content_md5']}",
                content_type="#{params['content_type']}",
                params="#{params['params']}",
                canonicalized_amz_headers=canonicalized_amz_headers
            )
        sign = Base64.encode64(OpenSSL::HMAC.digest('sha1',@secret_key,sign_str))
        return sign.rstrip
    end
    def generate_headers(method, path, params)
        request_date = (Time.new - 8*3600).strftime('%a, %d %b %Y %H:%M:%S GMT')
        sign = create_sign(method, path, params)
        authorization = "AWS" + " " + @access_key.to_s + ":" + sign
        header_data = Hash['Date' => request_date, 'Authorization' => authorization]
        if params.key?('x-amz-acl')
            header_data.update('x-amz-acl' => "#{params['x-amz-acl']}")
        end
        if params.key?('content_length')
            header_data.update('Content-Length' => "#{params['content_length']}")
        end
        header_data.update('Content-Type'=> "")
        if params.key?('content_type')
            header_data.update('Content-Type' => "#{params['content_type']}")
        end
        return header_data
    end
end

class Send_request < Create_Header
    @@host = "osc.speedycloud.net"
    def reqs(method,path,data,params)
        uri = URI.parse("http://"+@@host+path)
        http = Net::HTTP.new(uri.hostname)
        if method == "GET"
            resp, datas = http.get(path, generate_headers(method, path, params))
            return resp.body
        end
        if method == "POST"
            resp = http.post(path, data=data, header=generate_headers(method, path, params))
            return resp.body
        end
        if method == "PUT"
            resp = http.send_request("PUT",path,data=data,header=generate_headers(method, path, params))
            return resp.body
        end
        if method == "DELETE"
            resp, datas = http.delete(path, generate_headers(method, path, params))
            return resp.body
        end
    end
    def upload_big_data_put(method, path,data, params)
        uri = URI.parse("http://"+@@host+path)
        http = Net::HTTP.new(uri.hostname)
        resp = http.send_request("PUT",path,data=data,header=generate_headers(method, path, params))
        return resp.header['etag']
    end
end

class Object_storge < Send_request
    def get_path(path)
        base_path = "/"
        return "%s%s" % [base_path, path]
    end

    def list(bucket)
=begin
    查询桶内对象列表
    参数:
            bucket: 桶名
        注意： bucket参数为''时，可查看所有桶
=end
        rel_path = get_path bucket
        result = reqs "GET", rel_path, "none", {}
        return result
    end

    def create_bucket(bucket)
=begin
    创建存储桶
        参数:
            bucket: 桶名
=end
        rel_path = get_path bucket
        result = reqs "PUT", rel_path, nil, {}
        return result
    end

    def delete_bucket(bucket)
=begin
    注意： 在桶内没有对象的时候才能删除桶
        删除存储桶
        参数:
            bucket: 桶名
=end
        rel_path = get_path bucket
        result = reqs "DELETE", rel_path, "none", {}
        return result
    end

    def query_backet_acl(bucket)
=begin
    查询桶的权限
        参数:
            bucket: 桶名
=end
        rel_path = get_path "%s?acl" % bucket
        result = reqs "GET", rel_path, "none", {}
        return result
    end

    def query_object_acl(bucket, key)
=begin
    查询桶内对象的权限
        参数:
            bucket: 桶名
            key: 对象名
=end
        rel_path = get_path "%s/%s?acl" % [bucket, key]
        result = reqs "GET", rel_path, "none", {}
        return result
    end

    def delete_object_data(bucket, key)
=begin
    删除桶内非版本管理对象
        注意： 删除成功不是返回200
        参数:
            bucket: 桶名
            key: 对象名
=end
        rel_path = get_path "%s/%s" % [bucket, key]
        result = reqs "DELETE", rel_path, "none", {}
        return result
    end

    def delete_versioning_object(bucket, key, versionId)
=begin
    删除桶内版本管理对象
    参数:
        bucket: 桶名
        key: 对象名
        versionId: 对象名
=end
        rel_path = get_path "%s/%s?versionId=%s" % [bucket, key, versionId]
        result = reqs "DELETE", rel_path, "none", {}
        return result
    end

    def configure_versioning(bucket, status)
=begin
    设置版本控制
    参数:
        bucket: 桶名
        status: 状态("Enabled"或者"Suspended")
=end
        rel_path = get_path "%s?versioning" % bucket
        versioningBody = '<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>%s</Status></VersioningConfiguration>'
        body = versioningBody % status
        result = reqs "PUT", rel_path, data=body, params={}
        return result
    end

    def get_bucket_versioning(bucket)
        #查看当前桶的版本控制信息，返回桶的状态（"Enabled"或者"Suspended"或者""）
        rel_path = get_path "%s?versioning" % bucket
        result = reqs "GET", rel_path, "none", {}
    end

    def get_object_versions(bucket)
        #获取当前桶内的所有对象的所有版本信息
        rel_path = get_path "%s?versions" % bucket
        result = reqs "GET", rel_path, "none", {}
    end

    def download_object_data(bucket, key)
=begin
    下载桶内对象的数据
        参数:
            bucket: 桶名
            key: 对象名
=end
        rel_path = get_path "%s/%s" % [bucket, key]
        result = reqs "GET", rel_path, "none", {}
        return result
    end

    def update_bucket_acl(bucket, header_params={})
=begin
    修改桶的权限
        参数:
            bucket: 桶名
            header_params: 请求头参数， 是一个字典
                {'x-amz-acl':test}
                    test: 允许值
                        private：自己拥有全部权限，其他人没有任何权限
                        public-read：自己拥有全部权限，其他人拥有读权限
                        public-read-write：自己拥有全部权限，其他人拥有读写权限
                        authenticated-read：自己拥有全部权限，被授权的用户拥有读权限
=end
        rel_path = get_path "%s?acl" % bucket
        result = reqs "PUT", rel_path, nil, params=header_params
        return result
    end

    def update_object_acl(bucket, key, header_params={})
=begin
    修改桶内对象的权限
        参数:
            bucket: 桶名
            key: 对象名
            header_params: 请求头参数， 是一个字典
                Hash['x-amz-acl'=>'public-read']
                    test: 允许值
                        private：自己拥有全部权限，其他人没有任何权限
                        public-read：自己拥有全部权限，其他人拥有读权限
                        public-read-write：自己拥有全部权限，其他人拥有读写权限
                        authenticated-read：自己拥有全部权限，被授权的用户拥有读权限
=end
        rel_path = get_path "%s/%s?acl" % [bucket, key]
        result = reqs "PUT", rel_path, nil, params=header_params
    end

    def update_versioning_object_acl(bucket, key, versionId, header_params={})
=begin
        修改桶内版本管理对象的权限
            参数:
                bucket: 桶名
                key: 对象名
                versionId: 对象版本号
                header_params: 请求头参数， 是一个字典
                    Hash['x-amz-acl'=>'public-read']
                        test: 允许值
                            private：自己拥有全部权限，其他人没有任何权限
                            public-read：自己拥有全部权限，其他人拥有读权限
                            public-read-write：自己拥有全部权限，其他人拥有读写权限
                            authenticated-read：自己拥有全部权限，被授权的用户拥有读权限
=end
        rel_path = get_path "%s/%s?acl&versionId=%s" % [bucket, key, versionId]
        result = reqs "PUT", rel_path, nil, params=header_params
        return result
    end

   def storing_object_data(bucket, key, update_data, update_type, header_params={})
=begin
    创建存储桶内对象
        参数:
            bucket: 桶名
            key: 对象名
            update_data: 对象的内容（文件的路径/字符串）
            update_type: 对象内容类型 允许值 'file','string'
=end
        rel_path = get_path "%s/%s" % [bucket, key]
        if update_type == "data" or update_type == "string"
            update_content = update_data
            content_length = update_data.length
            content_md5 = Digest::MD5.hexdigest(update_content)
            result = reqs "PUT", rel_path, data=update_content, params=header_params
            return result
        end
        if update_type == "file"
            result = upload_big_data(bucket, key, update_data, header_params)
            return result
        end
    end

    def upload_big_data_one(bucket, key, header_params)
        rel_path = get_path "%s/%s?uploads" % [bucket, key]
        xml = reqs "POST", rel_path, nil, header_params
        roots = REXML::Document.new(xml)
        upload_id = roots.root.elements["UploadId"].text
        return upload_id
    end

    def upload_big_data_two(bucket, key, update_data, part_number, upload_id, header_params)
        update_content = update_data
        rel_path = get_path "%s/%s?partNumber=%s&uploadId=%s" % [bucket, key, part_number, upload_id]
        return upload_big_data_put("PUT", rel_path, update_content, header_params)
    end

    def upload_big_data(bucket, key, update_data, header_params)
        uid = upload_big_data_one(bucket, key, header_params)
        rel_path = get_path "%s/%s?uploadId=%s" % [bucket, key, uid]
        size = File::size?(update_data)
        rock = 1024.0 * 1024 * 20
        if !size
            return ""
        end
        if size > (1024.0 * 1024 * 1024)
            puts "file is bigger than 1G"
            return "file is bigger than 1G"
        end
        i = size / (1024.0 * 1024 * 20) #i = 1.5
        content = ""
        x = 0
        File.open(update_data, "r") do |f|
            while x < i
                chunk = f.read(rock)
                etag = upload_big_data_two(bucket, key, chunk, x+1, uid, header_params)
                content += "<Part><PartNumber>%s</PartNumber><ETag>%s</ETag></Part>" % [x+1, etag]
                x += 1
            end
        end
        content = '<CompleteMultipartUpload>' + content + '</CompleteMultipartUpload>'
        result = reqs "POST", rel_path, data=content, params=header_params
        return result
    end
end