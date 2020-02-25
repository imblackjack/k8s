%define debug_package           %{nil}
%global __os_install_post %{nil}

Name: bsc-flowdetect
Version: 1.80.1
Release: 1%{?dist}
Summary: flowdetect from bsc
Group:  Application/Server
License: GPL
URL: http://juhe.baishancloud.com
Prefix:     /usr/local/bsc/flowdetect
BuildRequires: rpm
Requires: zeromq
BuildArch: x86_64
autoreqprov: 0

%description
1. 系统日志事件支持自定义通知开关

%prep

%build

%install
cd %_topdir/SOURCES/firewall-api/firewallapi
/usr/local/bsc/bin/python3 /usr/local/bsc/bin/virtualenv cp37
. cp37/bin/activate
pip3 install -r ../requirement.txt -i http://pypi.douban.com/simple --trusted-host pypi.douban.com  --no-binary IPy --no-binary pylru --no-binary tornado --no-binary mysqlclient
/usr/local/bsc/bin/python3 /usr/local/bsc/bin/virtualenv --relocatable cp37

# fix tornado "Invalid x-www-form-urlencoded body: 'latin-1' codec can't encode characters"
sed -i 's#parse_qs_bytes(native_str(body),#parse_qs_bytes(body,#' cp37/lib/python3.7/site-packages/tornado/httputil.py
sed -i 's#qs, keep_blank_values,#qs.decode("latin1") if isinstance(qs, bytes) else qs, keep_blank_values,#' cp37/lib/python3.7/site-packages/tornado/escape.py
# fix salt "TypeError: string argument without an encoding"
sed -i 's#import logging#import logging\nimport binascii#' cp37/lib/python3.7/site-packages/salt/_compat.py
sed -i 's#packed.*bytearray.*$#packed = bool(int(str(binascii.hexlify(bytearray(data, encoding="utf8"))), 16))#' cp37/lib/python3.7/site-packages/salt/_compat.py
# fix salt "UnicodeDecodeError: 'utf-8' codec can't decode byte 0x82 in position 22: invalid start byte"
sed -i '280c\        self.unpacker = msgpack.Unpacker(raw=True)' cp37/lib/python3.7/site-packages/salt/transport/ipc.py
sed -i '145c\                    ret = msgpack.loads(msg, use_list=True, ext_hook=ext_type_decoder, raw=raw)' cp37/lib/python3.7/site-packages/salt/payload.py
# fix salt "KeyError: 'body'"
sed -i '656c\                        ret = framed_msg[b"body"]' cp37/lib/python3.7/site-packages/salt/transport/ipc.py
sed -i '659c\                        self.saved_data.append(framed_msg[b"body"])' cp37/lib/python3.7/site-packages/salt/transport/ipc.py

cd ..

mkdir -p %{buildroot}%{prefix}/
cp -ar firewallapi firewallapi_rule_clean.py %{buildroot}%{prefix}/
cd %{buildroot}%{prefix}/firewallapi/
chmod +x main.py
python3 -m compileall -b handlers utils __init__.py main.py ../firewallapi_rule_clean.py
rm -f handlers/*.py utils/*.py __init__.py ../firewallapi_rule_clean.py

%clean
rm -rf %{buildroot}
rm -rf %_topdir/SOURCES/firewall-api/firewallapi/cp37

%pre
if [ -d /usr/local/bsc/firewall-api/firewallapi/cp27 ];then rm -rf /usr/local/bsc/firewall-api/firewallapi/cp27;fi
if [ -d /usr/local/bsc/firewall-api/ ];then find /usr/local/bsc/firewall-api/ -maxdepth 3 -name '*.py' -print -delete;fi

%post
if [ -f /usr/local/bsc/firewall-api/data.db ];then rm -f /usr/local/bsc/firewall-api/data.db;fi

%files
%{prefix}

%changelog
