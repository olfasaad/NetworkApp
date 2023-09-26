from asyncio import tasks
from concurrent.futures import thread
from distutils.command.config import config
from distutils.log import debug, error
from enum import unique
from fileinput import filename
from imp import reload
from platform import platform
from re import template
from tokenize import Name
from unittest import result
from flask import Flask,flash,render_template,redirect,request,url_for, session
from flask_mail import Mail, Message
from netmiko import Netmiko
from nornir_netmiko import netmiko_send_config,netmiko_send_command
#from requests import session 
from controller.controller import connect,get_interfaces_list 
from controller.arp import connx ,get_interfaces
from jinja2 import Environment,FileSystemLoader
from nornir import InitNornir
import os
from nornir.core.filter import F
from nornir_utils.plugins.functions import print_result 
from nornir_napalm.plugins.tasks import napalm_get
from nornir.core.task import AggregatedResult
from flask_sqlalchemy import SQLAlchemy
from datetime import date
import sqlite3
import csv
import sys
import pandas as pd
import numpy as np
from nornir_utils.plugins.tasks.files import write_file
from pathlib import Path
import pathlib
import pyshark
from wtforms_sqlalchemy.fields import QuerySelectField
from flask_wtf import FlaskForm

app = Flask(__name__) #nom de l'application
#initialiation nornir
#nr = InitNornir(config_file="config.yaml")

#this line connect our app file to database 

app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database/data.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY']='saadolfa1' #use to secure session
db=SQLAlchemy(app)

class USER(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(20))
    password = db.Column(db.String(100))
    def __init__(self,user,password) -> None:
        self.user=user
        self.password=password
       
db.create_all()   
class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    hostname = db.Column(db.String(100))
    platform = db.Column(db.String(100))
    port = db.Column(db.Integer)
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    secret = db.Column(db.String(100))
    groups = db.Column(db.String(100))  
    #consctruacteur 
    def __init__(self, name, hostname, platform,port,username,password,secret,groups):

        self.name = name
        self.hostname = hostname
        self.platform = platform
        self.port = port
        self.username = username
        self.password = password
        self.secret = secret
        self.groups = groups

      
db.create_all()

#//////////////log

#///////////////////dashborad//////////////////////
@app.route('/dash')
def dash():
 if session.get('logged_in'):
    all_data = Data.query.all()
    
    f = open('inventory.csv', 'w',newline='')
    out = csv.writer(f)
    out.writerow(['name', 'hostname', 'port','username','password','secret','groups'])
    for item in Data.query.all():
        out.writerow([item.name,item.hostname,item.port, item.username, item.password,item.secret,item.groups])
        #print("Printing CSV Data..")
    f.close()
   
    long=len(all_data)
    return render_template('dashbord.html',x=all_data,long=long)
 else:
    return render_template('log2.html')
@app.route('/insert',methods=['POST'])
def insert():
    if request.method =='POST':
        name=request.form['name']
        hostname=request.form['hostname']
        platform=request.form['platform']
        port=request.form['port']
        username=request.form['username']
        password=request.form['password']
        secret=request.form['secret']
        groups=request.form['groups']
        my_data = Data(name, hostname, platform,port,username,password,secret,groups)
        db.session.add(my_data)
        db.session.commit()
        flash("Device Inserted Successfully") 
        return redirect(url_for('dash'))
# This route is for deleting our Record
@app.route('/delete/<id>/', methods=['GET', 'POST'])
def delete(id):
    my_data = Data.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
    flash("Device Deleted Successfully")

    return redirect(url_for('dash'))
#///////////////////////////page update///////////////////
@app.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == 'POST':
        my_data = Data.query.get(request.form.get('id'))

        my_data.name = request.form['name']
        my_data.hostname = request.form['hostname']
        my_data.platform = request.form['platform']
        my_data.port = request.form['port']
        my_data.username = request.form['username']
        my_data.password = request.form['password']
        my_data.secret = request.form['secret']
        my_data.groups = request.form['groups']

        db.session.commit()
        flash("Device Updated Successfully")

        return redirect(url_for('dash'))

#Class for CSV TO YAML////////////////////////
class Csv2NornirSimple:

    def __init__(self, filename):
        self.filename = filename
        self.inventory_data = []

    def inventory_converter(self):
        inventory_list = []
        # Currently not in use

        try:
            with open(self.filename) as csv_file:
                csv_reader = csv.DictReader(csv_file)
                for row in csv_reader:
                    inventory_list.append([
                        row["name"],
                        row["hostname"],
                        row["port"],
                        row["username"],
                        row["password"],
                        row["secret"],
                        row["groups"],
                      



                    ])
                self.inventory_data = inventory_list
        except FileNotFoundError:
            print(f"Please make sure that filename is correct and exists...")
            sys.exit(1)


    # Iterates over the list and creates the hosts.yaml based on the Nornir model

    def make_nornir_inventory(self):
        if len(self.inventory_data) < 1:
            print("The list argument doesn't have any records! Cannot create an inventory file out of an empty list!")
            return ValueError
        try:

            with open("inventory/hosts.yaml", "w") as out_file:
                out_file.write("---\n")
                for host in self.inventory_data:
                    out_file.write(f"{host[0]}:\n")
                    out_file.write(f"  hostname: {host[1]}\n")
                    out_file.write(f"  port: {host[2]}\n")
                    out_file.write(f"  username: {host[3]}\n")
                    out_file.write(f"  password: {host[4]}\n")
                    out_file.write(f"  secret: {host[5]}\n")

                    if len(host[6].split("_")) > 0:
                        out_file.write(f"  groups:\n")
                        for group in host[6].split("__"):
                            out_file.write(f"    - {group}\n")

                    else:
                        out_file.write("\n")
         
                print("Inventory file created...")
        except PermissionError:
            print("An error occurred whilst trying to write into the file... Please make sure that there are enough permission assigned to the user executing the script...")
            sys.exit(1)

csv2n = Csv2NornirSimple("inventory.csv")
inventory_list = csv2n.inventory_converter()
csv2n.make_nornir_inventory()


#//////////////////////test inventory
nr = InitNornir(config_file="config.yaml")
#///////////////////////////page login///////////////////
@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('log2.html')
    else:
        u = request.form['username']
        p = request.form['password']
        dat = USER.query.filter_by(user=u, password=p).first()
        if dat is not None:
            session['logged_in'] = True
            return redirect(url_for('dash'))
        else:
          return render_template('log2.html',error="Incorrect Details")
###///////////////////////////logout
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session['logged_in'] = False
    return redirect(url_for('login'))
#///////////////Facts\\\\\\\\\\\\\\\\\\\\\\\\
@app.route('/home') #route 
def hello():
 if session.get('logged_in'):
    return render_template ("home.html",title="home")
 else:
     return render_template("log2.html")
@app.route('/home',methods = ['POST','GET']) #route 
def home1():
 if session.get('logged_in'):
    nr = InitNornir(config_file="config.yaml")
    dev=request.form['choix1']
    gett=request.form['choix']
   
    if gett == 'Facts': # If the NAPALM getter is = facts
        #Nornir to run napalm getters e.g. facts
        getter_output = nr.run(task=napalm_get, getters=["facts"])
        #Print napalm getters output via print_result function
        print_result(getter_output)
        list = []
        try:
            #For loop to get interusting values from the multiple devices output
            for host, task_results in getter_output.items():
                #Get the device facts result
                device_output = task_results[0].result
                data = {}
                data["host"] = host
                #From Dictionery get vendor name
                data["vendor"] = device_output["facts"]["vendor"]
                #From Dictionery get model
                data["model"] = device_output["facts"]["model"]
                # From Dictionery get version
                data["version"] = device_output["facts"]["os_version"]
                # From Dictionery get serial
                data["ser_num"] = device_output["facts"]["serial_number"]
                # From Dictionery get uptime
                data["uptime"] = device_output["facts"]["uptime"]
                # Append results to a list to be passed to facts.html page
                list.append(data)
            #print (list)
            return render_template("home.html", resfac=list)      # Send the values of list to the next page for printing
        except:
            return render_template("home.html", noresfac="No Response from Device")
    elif gett == 'Interface':  # If the NAPALM getter is = Interface IP
        #Nornir to run napalm getters interfaces_ip
        getter_output = nr.run(task=napalm_get, getters=["interfaces_ip"])
        #Print napalm getters output via print_result function
        print_result(getter_output)
        list = []
        try:
            #For loop to get interusting values from the output
            for host, task_results in getter_output.items():
                #Get the device interface ip result
                device_output = task_results[0].result
                #print (device_output)
                interface_ip = device_output["interfaces_ip"]
                #print (interface_ip)
                for inte, val in interface_ip.items():
                    data = {}
                    data["host"] = host
                    data["interface"] = inte
                    data["ip_address"] = val["ipv4"].popitem()[0]
                    list.append(data)
            return render_template("interfaceip.html", resint=list)      # Send the values of list to the next page for printing
        except:
            return render_template("interfaceip.html", noresint="No Response from Device")
 else:
     return render_template("log2.html")
      
#/////////////// interface list
@app.route('/service',methods = ['POST','GET'])
def ser():
  if session.get('logged_in'):
    if request.method == 'POST':
        result = request.form.to_dict()
        device = connect('cisco_ios', result['hostname'], result['username'], result['password'] , result['port'])
        return render_template('service.html', result=get_interfaces_list(device))
    else:
        return render_template('service.html')  
   
  else:
    return render_template('log2.html')

#///////////// arp page
@app.route('/arp',methods = ['POST','GET'])
def arp():
 if session.get('logged_in'):
    if request.method == 'POST':
        result = request.form.to_dict()
        device = connect('cisco_ios', result['hostname'], result['username'], result['password'] , result['port'])
        return render_template('servarp.html', result=get_interfaces(device))
    else:
        return render_template('servarp.html')  
 else:
     return render_template("log2.html") 
#//////////////////////// Vlan page ////////////
@app.route('/vlan')  
def vlan1():
  if session.get('logged_in'):
    return render_template('vlan.html')
  else:
      return render_template("log2.html")
@app.route('/vlan',methods = ['POST','GET'])  
def vlan():
 if session.get('logged_in'):
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        input1 = request.form
        name1=request.form.get('Router')
        env=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True,)
        template=env.get_template('vlan.j2')
        result=template.render(input1)
        vlan_send = result.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
       
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
       
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))

        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def automate(job):
            job.run(task=netmiko_send_config,name="Pushing VLAN Commands",config_commands=vlan_send)
        results=hosts1.run(task=automate)
        df=pd.DataFrame(results)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results)
        return render_template('vlan.html',x=y,result=result,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
 else:
     return render_template("log2.html")
#////////////////////////dhcp page ////////////
@app.route('/dhcp')  
def dhcp():
  if session.get('logged_in'):
    return render_template('dhcp.html')
  else:
      return render_template("log2.html")
@app.route('/dhcp',methods = ['POST','GET'])  
def dhcp1():
 if session.get('logged_in'):
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        input2 = request.form
        name1=request.form.get('Router')
        env1=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True)
        template1=env1.get_template('dhcp.j2')
        result2=template1.render(input2)
        dhcp_send = result2.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
       
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
       
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))

        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def automate1(job):
            job.run(task=netmiko_send_config,name="Pushing DHCP Commands",config_commands=dhcp_send)
        results2=hosts1.run(task=automate1)
        df=pd.DataFrame(results2)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results2)
        return render_template('dhcp.html',x=y,result2=result2,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
 else:
      return render_template("log2.html")
##//////////////////////// route stat page ////////////
@app.route('/routestat')  
def routestat():
  if session.get('logged_in'):
    return render_template('routestat.html')
  else:
      return render_template("log2.html")
@app.route('/routestat',methods = ['POST','GET'])  
def routestat1():
 if session.get('logged_in'):
  try:    #nr.data.reset_failed_hosts()
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        input3 = request.form
        name1=request.form.get('Router')
        env1=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True,)
        template1=env1.get_template('routestat.j2')
        result3=template1.render(input3)
        route_send = result3.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
       
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
       
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))
        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def automate1(job):
            job.run(task=netmiko_send_config,name="Pushing STATIC ROUTE Commands",config_commands=route_send)
        results3=hosts1.run(task=automate1)
        df=pd.DataFrame(results3)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results3)
    
        return render_template('routestat.html',x=y,result3=result3,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
  except:
        return render_template("routestat.html", noresfac="No Response from Device")
 else:
     return render_template("log2.html")
#//////////////////////// access page ////////////
@app.route('/access')  
def access():
  if session.get('logged_in'):
    return render_template('access.html')
  else:
      return render_template("log2.html")
@app.route('/access',methods = ['POST','GET'])  
def access1():
 if session.get('logged_in'):   
  try:    #nr.data.reset_failed_hosts()
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        input4 = request.form
        name1=request.form.get('Router')
        env1=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True)
        template1=env1.get_template('access.j2')
        result3=template1.render(input4)
        access_send = result3.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
       
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
       
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))
        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def access2(job):
            job.run(task=netmiko_send_config,name="Pushing ACCESS PORT Commands",config_commands=access_send)
        res4=hosts1.run(task=access2)
        df=pd.DataFrame(res4)
        y=df.to_string()
        hosts1.close_connections()
        print_result(res4)
    return render_template('access.html',x=y,result3=result3,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
  except:
        return render_template("access.html", noresfac="No Response from Device")
 else:
     return render_template("log2.html")  
#//////////////////////// trunk page ////////////
@app.route('/trunk')  
def trunk():
  if session.get('logged_in'):
    return render_template('trunk.html')
  else:
      return render_template("log2.html")
@app.route('/trunk',methods = ['POST','GET'])  
def trunk1():
 if session.get('logged_in'):   
  try:    #nr.data.reset_failed_hosts()
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        input5 = request.form
        name1=request.form.get('Router')
        env1=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True,)
        template1=env1.get_template('trunk.j2')
        result3=template1.render(input5)
        trunk_send = result3.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
       
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
       
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))
        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def trunk2(job):
            job.run(task=netmiko_send_config,name="Pushing TRUNK PORT Commands",config_commands=trunk_send)
        res3=hosts1.run(task=trunk2)
        df=pd.DataFrame(res3)
        y=df.to_string()
        hosts1.close_connections()
        print_result(res3)
    return render_template('trunk.html',x=y,result3=result3,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
  except:
        return render_template("trunk.html", noresfac="No Response from Device")
 else:
     return render_template("log2.html")
#//////////////////////// ospf page ////////////
@app.route('/ospf')  
def ospf(): 
  if session.get('logged_in'):
    return render_template('ospf.html')
  else:
      return render_template("log2.html")
@app.route('/ospf',methods = ['POST','GET'])  
def ospf1():
  if session.get('logged_in'):
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        ospf2= request.form
        name1=request.form.get('Router')
        env=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True,)
        template=env.get_template('ospf.j2')
        result3=template.render(ospf2)
        ospf_send = result3.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
       
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
       
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))
        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def autoospf(job):
            job.run(task=netmiko_send_config,name="Pushing OSPF Commands",config_commands=ospf_send)
        results=hosts1.run(task=autoospf)
        df=pd.DataFrame(results)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results)
       
        print(name1)
    return render_template('ospf.html',x=y,name1=name1,result3=result3,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
  else:
      return render_template("log2.html")
#//////////////////////// access list page ////////////
@app.route('/aclst')  
def acls():
  if session.get('logged_in'):
    return render_template('aclst.html')
  else:
      return render_template("log2.html")
@app.route('/aclst',methods = ['POST','GET'])  
def acls1():
 if session.get('logged_in'):
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        acl= request.form 
        name1=request.form.get('Router')
        env=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True,)
        template=env.get_template('stand.j2')
        result3=template.render(acl)
        acl_send = result3.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
       
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
       
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))
        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def autoospf(job):
            job.run(task=netmiko_send_config,name="Pushing Access List Commands",config_commands=acl_send)
        results=hosts1.run(task=autoospf)
        df=pd.DataFrame(results)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results)
        
    return render_template('aclst.html',x=y,results=results,result3=result3,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
 else:
      return render_template("log2.html")
#////////////////////////acl extend page ////////////
@app.route('/aclex')  
def exs():
  if session.get('logged_in'):
    return render_template('aclex.html')
  else:
      return render_template("log2.html")
@app.route('/aclex',methods = ['POST','GET'])  
def exs1():
 if session.get('logged_in'):
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        aclex= request.form 
        name1=request.form.get('Router')
        env=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True,)
        template=env.get_template('extnd.j2')
        result3=template.render(aclex)
        ex_send = result3.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
              
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))

        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def autoacl(job):
            job.run(task=netmiko_send_config,name="Pushing Access List Commands",config_commands=ex_send)
        results=hosts1.run(task=autoacl)
        df=pd.DataFrame(results)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results)
        
    return render_template('aclex.html',x=y,results=results,result3=result3,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
 else:
      return render_template("log2.html")
   
#//////////////////////// delete page ////////////
@app.route('/delete')  
def dell():
  if session.get('logged_in'):
    return render_template('delete.html')
  else:
      return render_template("log2.html")
@app.route('/delete',methods = ['POST','GET'])  
def dell1():
  if session.get('logged_in'):
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        de = request.form['conf']
        name1=request.form.get('Router')
        del_send = de.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
       
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
       
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))

        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def autodel(job):
            job.run(task=netmiko_send_config,name="Pushing DElete Commands",config_commands=del_send)
        results=hosts1.run(task=autodel)
        df=pd.DataFrame(results)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results)
        
    return render_template('delete.html',x=y,results=results,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
  else:
      return render_template("log2.html")
#//////////////////////// config ip router
@app.route('/router')  
def router():
 if session.get('logged_in'):
    return render_template('router.html')
 else:
      return render_template("log2.html")
@app.route('/router',methods = ['POST','GET'])  
def router1():
  if session.get('logged_in'):
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        de = request.form
        name1=request.form.get('Router')
        env=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True,)
        template=env.get_template('router.j2')
        result3=template.render(de)
        ip_send = result3.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif name1=="all":
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
        else:
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
 
        def autoconf(job):
            job.run(task=netmiko_send_config,name="Pushing IP Configuration  Commands",config_commands=ip_send)
        results=hosts1.run(task=autoconf)
        df=pd.DataFrame(results)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results)
        
    return render_template('router.html',x=y,result3=result3,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
  else:
      return render_template("log2.html")
#//////////////////////// config ip switch
@app.route('/switch')  
def switch():
 if session.get('logged_in'):
    return render_template('switch.html')
 else:
      return render_template("log2.html")
@app.route('/switch',methods = ['POST','GET'])  
def switch1():
  if session.get('logged_in'):
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        de = request.form
        name1=request.form.get('Router')
        env=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True,)
        template=env.get_template('switch.j2')
        result3=template.render(de)
        ip_send = result3.splitlines()
        if name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))
       
        elif name1=="all":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
        else:
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
        def autoconf(job):
            job.run(task=netmiko_send_config,name="Pushing IP Configuration  Commands",config_commands=ip_send)
        results=hosts1.run(task=autoconf)
        df=pd.DataFrame(results)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results)
        
    return render_template('switch.html',x=y,result3=result3,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
  else:
      return render_template("log2.html")   
#//////////////////////// config ftp server
@app.route('/ftp')  
def ftp():
  if session.get('logged_in'):
    return render_template('ftp.html')
  else:
      return render_template("log2.html")
@app.route('/ftp',methods = ['POST','GET'])  
def ftp1():
 if session.get('logged_in'):
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        ftp= request.form 
        name1=request.form.get('Router')
        env=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True,)
        template=env.get_template('ftp.j2')
        result3=template.render(ftp)
        ftp_send = result3.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
       
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
       
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))
        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def autoftp(job):
            job.run(task=netmiko_send_config,name="Pushing FTP Commands",config_commands=ftp_send)
        results=hosts1.run(task=autoftp)
        df=pd.DataFrame(results)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results)
       
    return render_template('ftp.html',x=y,result3=result3,res=nr.data.failed_hosts,olfa=len(nr.data.failed_hosts))
 else:
      return render_template("log2.html")
#//////////////////////// config ping
@app.route('/ping')  
def ping():
  if session.get('logged_in'):
    return render_template('ping.html')
  else:
      return render_template("log2.html")
@app.route('/ping',methods = ['POST','GET'])  
def ping1():
 if session.get('logged_in'):
    nr.data.reset_failed_hosts()
    if request.method == "POST":
        dex= request.form
        name1=request.form.get('Router')
        env=Environment(loader=FileSystemLoader('./templates'),trim_blocks=True,lstrip_blocks=True,)
        template=env.get_template('ping.j2')
        result3=template.render(dex)
        ip_send =result3.splitlines()
        if name1 =="Router1" :
            hosts1=nr.filter(F(hostname='192.168.175.11'))
        elif name1 =="Router2" :
            hosts1=nr.filter(F(hostname='192.168.175.12'))
        elif name1 =="Router3" :
            hosts1=nr.filter(F(hostname='192.168.175.13'))
        elif name1 =="Router4" :
            hosts1=nr.filter(F(hostname='192.168.175.18'))
        elif name1 =="Router5" :
            hosts1=nr.filter(F(hostname='192.168.175.19'))
        elif (name1 =="Router1" or name1 =="Router2" or name1 =="Router3"or name1 =="Router4" or name1 =="Router5"):
            hosts1=nr.filter(F(groups__contains='IOS_Routers'))
       
        elif name1 =="Switcher1" and name1 =="Switcher2" and name1 =="Switcher3":
            hosts1=nr.filter(F(groups__contains='IOS_Switches'))
       
        elif name1 =="Switcher1" :
            hosts1=nr.filter(F(hostname='192.168.175.14'))
       
        elif name1 =="Switcher2" :
            hosts1=nr.filter(F(hostname='192.168.175.15'))
        elif name1 =="Switcher3" :
            hosts1=nr.filter(F(hostname='192.168.175.16'))
        elif name1=="all":
            hosts1=nr
        else:
            hosts1=nr
        def autoping(job):
            job.run(task=netmiko_send_config,name="Pushing PING Commands",config_commands=ip_send)
        results=hosts1.run(task=autoping)
        df=pd.DataFrame(results)
        y=df.to_string()
        hosts1.close_connections()
        print_result(results)
        
    return render_template('ping.html',x=y)
 else:
     return render_template("log2.html")

#/////////////////////////SaveShowCommandOutPutbyGroup/////////////////////////
@app.route('/saveshowcommand', methods=['GET', 'POST'])
def saveshowcommand():

    group = request.form.get('group')
    command=request.form.get('command')

    def show_configurations(task):
        config_dir = "ShowCommand-archive"
        date_dir = config_dir + "/" + str(date.today())
        command_dir = date_dir + "/" + command
        pathlib.Path(config_dir).mkdir(exist_ok=True)
        pathlib.Path(date_dir).mkdir(exist_ok=True)
        pathlib.Path(command_dir).mkdir(exist_ok=True)
        r = task.run(task=netmiko_send_command, command_string=command)
        task.run(task=write_file,content=r.result,
            filename=f"" + str(command_dir) + "/" + task.host.name + ".txt",
        )
       
    nr = InitNornir(config_file="config.yaml")
    nr.data.reset_failed_hosts()
    hosts=nr.filter(F(groups__contains=group))
    
    result = hosts.run(name="Creating Show Command Backup Archive", task=show_configurations)
    df=pd.DataFrame(result)
    y=df.to_string()
    return render_template('save.html',x=y,result=nr.data.failed_hosts,l1=len(nr.data.failed_hosts) )


#///////////////////////////////////SaveShowCommandOutPutbyName///////////////////////////////////
@app.route('/saveshowcommand1', methods=['GET', 'POST'])
def saveshowcommand1():

    name = request.form.get('group1')
    command1=request.form.get('command1')

    def show_configurations(task):
        config_dir = "ShowCommand-archive"
        date_dir = config_dir + "/" + str(date.today())
        command_dir = date_dir + "/" + command1
        pathlib.Path(config_dir).mkdir(exist_ok=True)
        pathlib.Path(date_dir).mkdir(exist_ok=True)
        pathlib.Path(command_dir).mkdir(exist_ok=True)
        r = task.run(task=netmiko_send_command, command_string=command1)
        task.run(task=write_file,content=r.result,filename=f"" + str(command_dir) + "/" + task.host.name + ".txt",)
    nr = InitNornir(config_file="config.yaml")
    hosts=nr.filter(F(name__contains=name))

    result = hosts.run(name="Creating Show Command Backup Archive", task=show_configurations)

    return render_template('save.html',results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))
@app.route('/save' )
def save1():
   return render_template('save.html')
#/////////////////////
def choice_query():
    return Data.query
class ChoiceForm(FlaskForm):
    opts= QuerySelectField(query_factory=choice_query,allow_blank=True)


if __name__=="__main__":
    app.run(debug=True)