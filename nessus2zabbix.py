#This takes as input a .nessus scan file with either vulnerability or compliance info (or both)
#and passes it to zabbix.
#
#Zabbix keys:
#
#cis.compliance.failed
#cis.compliance.passed
#cis.compliance.warning
#nessus.policy.name
#nessus.scan.name
#nessus.date.latest.scan
#vulnerability.critical
#vulnerability.high
#vulnerability.low
#vulnerability.medium

#autor: @Ar0xA / ar0xa@tldr.nu

from bs4 import BeautifulSoup

import argparse
import sys
import os

from pyZabbixSender import pyZabbixSender #local import from https://github.com/kmomberg/pyZabbixSender/blob/master/pyZabbixSender.py


#here we parse results from the nessus file, we extract the vulnerabiltiy results and return that in an array
#in the format [ ['hostname', int(low), int(Medium), int(High), int(Critical)], [etc.] ]
def parse_vuln_results(hosts):
    print "Checking for vulnerability results..."
    tmp_res=[]
    is_data = False
    for host in hosts:
        low = 0
        medium = 0
        high = 0
        critical = 0
        host_name = host['name']
        #lets iterate through the reportItem, here the compliance items will be
        reportItems = host.findAll('reportitem')
        for rItem in reportItems:
            #ok, so we need to find  all report items that do NOT include <compliance>true</compliance>
            try:
                vuln_item = rItem.find('compliance')
                risk_factor = rItem.find('risk_factor')
                if (vuln_item) == None and ( risk_factor.get_text() == 'Low'):
                    low += 1
                    is_data = True
                elif (vuln_item) == None and ( risk_factor.get_text() == 'Medium'):
                    medium += 1
                    is_data = True
                elif (vuln_item) == None and ( risk_factor.get_text() == 'High'):
                    high += 1
                    is_data = True
                elif (vuln_item) == None and ( risk_factor.get_text() == 'Critical'):
                    critical += 1
                    is_data = True
            except:
                print rItem
                sys.exit(1)
        print '%s has %i vulnerabilies low, %i medium, %i high, %i critical' % (host_name, low, medium, high, critical)
        tmp_res.append([host_name, low, medium, high, critical])
    #ok look, if everything is 0...lets just give up
    if is_data:
        return tmp_res
    else:
        return []

#here we parse results from the nessus file, we extract the compliance results and return that in an array
#in the format [ ['hostname', int(passed), int(warning), int(failed)], [etc.] ]
def parse_comp_results(hosts):
    print "Checking for compliance results..."
    tmp_res=[]
    is_data = False
    # lets go through each host
    for host in hosts:
        failed = 0
        passed = 0
        warning = 0
        host_name = host['name']
        #lets iterate through the reportItem, here the compliance items will be
        reportItems = host.findAll('reportitem')
        for rItem in reportItems:
            #ok lets find all compliance result items, and ONLY compliance items
            try:
                compliance_item = rItem.find('cm:compliance-result')
                if (compliance_item != None) and(compliance_item.get_text() == 'PASSED'):
                    passed += 1
                    is_data = True
                elif(compliance_item != None) and(compliance_item.get_text() == 'FAILED'):
                    failed += 1
                    is_data = True
                elif(compliance_item != None) and(compliance_item.get_text() == 'WARNING'):
                    warning += 1
                    is_data = True
            except:
                print rItem
                sys.exit(1)
        print '%s has %i compliance passed, %i warnings and %i failed' % (host_name, passed, warning, failed)
        tmp_res.append([host_name, passed, warning, failed])

    #look ok, if everything is 0 lets just give up
    if is_data:
        return tmp_res
    else:
        return []

#Send compliance data to Zabbix
def send_comp_to_zabbix(compliance_results, args_server, args_port, nessus_metadata, args_fake):
    z = pyZabbixSender(server=args_server, port=args_port)

    for comp_result in compliance_results:
        #first we add the metadata
        z.addData(comp_result[0],'nessus.scan.name',nessus_metadata[0]) #scanname
        z.addData(comp_result[0],'nessus.policy.name',nessus_metadata[1]) #policyname
        z.addData(comp_result[0],'nessus.date.latest.scan',nessus_metadata[2]) #scan time
        #now we add the values
        z.addData(comp_result[0], 'cis.compliance.passed', comp_result[1])
        z.addData(comp_result[0], 'cis.compliance.warning', comp_result[2])
        z.addData(comp_result[0], 'cis.compliance.failed', comp_result[3])

        #debug
        #z.printData()
        if args_fake == "False":
            results = z.sendDataOneByOne()
            for (code,data) in results:
                if code != z.RC_OK:
                    print "Failed to send %s" % str(data)
        else:
            print "Faking. This is where I send data"
        z.clearData()
    print "Done sending compliance data"

def send_vuln_to_zabbix(vulnerability_results, args_server, args_port, nessus_metadata, args_fake):
    z = pyZabbixSender(server=args_server, port=args_port)

    for vuln_result in vulnerability_results:
        #first we add the metadata
        z.addData(vuln_result[0],'nessus.scan.name',nessus_metadata[0]) #scanname
        z.addData(vuln_result[0],'nessus.policy.name',nessus_metadata[1]) #policyname
        z.addData(vuln_result[0],'nessus.date.latest.scan',nessus_metadata[2]) #scan time
        #now we add the values
        z.addData(vuln_result[0], 'vulnerability.low', vuln_result[1])
        z.addData(vuln_result[0], 'vulnerability.medium', vuln_result[2])
        z.addData(vuln_result[0], 'vulnerability.high', vuln_result[3])
        z.addData(vuln_result[0], 'vulnerability.critical', vuln_result[4])

        #debug
        #z.printData()
        if args_fake == "False":
            results = z.sendDataOneByOne()
            for (code,data) in results:
                if code != z.RC_OK:
                    print "Failed to send %s" % str(data)
        else:
            print "Faking. This is where I send data"
        z.clearData()
    print "Done sending vulnerability data"


def main():
    parser = argparse.ArgumentParser(description = 'Push data into zabbix from a .nessus result file.')
    parser.add_argument('-i', '--input', help = 'Input file in .nessus format',
        default = None)
    parser.add_argument('-s', '--server', help = 'Zabbix server',
        default = '127.0.0.1')
    parser.add_argument('-p', '--port', help = 'Zabbix port',
        default = 10051)
    parser.add_argument('-t', '--type', help = 'What type of result to parse the file for.', choices = ['both', 'vulnerability','compliance' ],
        default = 'both')
    parser.add_argument('-f','--fake', help='Do everything but actually send data to Zabbix', choices = ['True','False'], default='False')
    args = parser.parse_args()

    if not args.input:
        print('Need input file. Specify one with -i')
        sys.exit(1)

    # read the file..might be big though...
    try:
        f = open(args.input, 'r')
    except:
        print 'File %s not found!' % args.input
        sys.exit(1)

    print 'Parsing file %s as xml into memory, hold on...' % (args.input)

    nessus_xml_data = BeautifulSoup(f.read(), 'lxml')

    #find metadata we need
    #todo: if not find items..is this valid nessus file?
    tmp_scanname = nessus_xml_data.report['name']
    if not len(tmp_scanname) > 0:
        print 'Didn\'t find report name in file. is this a valid nessus file?'
        sys.exit(1)

    tmp_policyname = nessus_xml_data.find('policyname').get_text()
    tmp_scantime = ""
    #scan is the first HOST_START that we find
    tmp_tags = nessus_xml_data.reporthost.findAll('tag') #tag['name'']
    for tag in tmp_tags:
        if tag['name'] ==  'HOST_START':
            tmp_scantime = tag.get_text()

    nessus_metadata= [tmp_scanname, tmp_policyname, tmp_scantime]

    # see if there are any hosts that are reported on
    hosts = nessus_xml_data.findAll('reporthost')
    if len(hosts) == 0:
        print 'Didn\'t find any hosts in file. Is this a valid nessus file?'
        sys.exit(1)
    else:
        print 'Found %i hosts' % (len(hosts))

    if args.type == "both" or args.type == "compliance":
        #ok now that we have the compliance results, lets make some magic!
        compliance_result = []
        compliance_result = parse_comp_results(hosts)
        if len(compliance_result) > 0:
            print "Sending compliance info to Zabbix server: %s" % (args.server)
            send_comp_to_zabbix(compliance_result, args.server, args.port, nessus_metadata, args.fake)
        else:
            print "Did not find any compliance items, not sending any information\n"

    if args.type == "both" or args.type == "vulnerability":
        vulnerability_result = []
        vulnerability_result = parse_vuln_results(hosts)
        if len(vulnerability_result) >0:
            print "Sending vulnerability info to Zabbix server: %s" % (args.server)
            send_vuln_to_zabbix(vulnerability_result, args.server, args.port, nessus_metadata, args.fake)
        else:
            print "Did not find any vulnerability items, not sending any information\n"

if __name__ == "__main__":
  main()
