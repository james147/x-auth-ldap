# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"
  config.vm.network "forwarded_port", guest: 80, host: 3000
  config.vm.provision "shell", inline: <<-SHELL
    apt-get install -y nginx
    cp /vagrant/nginx.example.conf /etc/nginx/sites-available/default
    service nginx restart
  SHELL
end
