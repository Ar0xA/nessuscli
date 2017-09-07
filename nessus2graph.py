#This takes as input a .nessus scan file with either vulnerability or compliance info (or both)
#and outputs a horizontal barchar per host, and a total average piechart with PASSED,
#WARNING and FAILED 's.
#
#autor: @Ar0xA / ar0xa@tldr.nu

from bs4 import BeautifulSoup

# we dont use X - Server hack
import matplotlib as mpl
mpl.use('Agg')

#set pyplot defaults, dont know why but it works
import matplotlib.pyplot as plt;
plt.rcdefaults()

import numpy as np
import argparse
import sys
import os

#make an average piechart from vulnerability_result into export_file. the args_format is the fileformat of export_file
def make_vuln_avg_piechart(vulnerability_result, export_file, args_format, args_dir):

    #calculate average passed, warning, failed
    server_count = len (vulnerability_result)

    all_low = 0
    for result in vulnerability_result:
        all_low += result[1]

    all_medium = 0
    for result in vulnerability_result:
        all_medium += result[2]

    all_high = 0
    for result in vulnerability_result:
        all_high += result[3]

    all_critical = 0
    for result in vulnerability_result:
        all_critical += result[4]

    total_items = (all_low + all_medium + all_high + all_critical) / server_count
    avg_low = round(float(all_low / server_count) / total_items*100,2)
    avg_medium = round(float(all_medium / server_count) / total_items*100,2)
    avg_high = round(float(all_high / server_count) / total_items*100,2)
    avg_critical = round(float(all_critical / server_count) / total_items*100,2)

    #now, lets make the piechart!
    labels = 'Low', 'Medium', 'High', 'Critical'
    colors = ["green", "yellow","#EE9336","red"]
    sizes = [avg_low, avg_medium, avg_high, avg_critical]

    fig = plt.figure(figsize = (10, 10), frameon = False)
    ax = fig.add_subplot(111)
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')
    ax.set_title(export_file + " - total avg")
    plt.savefig(args_dir + '/' + export_file.replace(' ', '_') + '_vuln_pie.'+ args_format)

#make a horizontal barchart from vulnerability_result into export_file. the args_format is the fileformat of export_file
def make_vuln_hbarchart(vulnerability_result,export_file,args_format, args_dir):
    all_servers = []
    # x items do not change through this
    for result in vulnerability_result:
        all_servers.append(result[0])

    low_data = []
    for result in vulnerability_result:
        low_data.append(result[1])
    low_data = np.array(low_data) #needs to be array to use the correct positioning in ax.barh left=

    medium_data = []
    for result in vulnerability_result:
        medium_data.append(result[2])
    medium_data = np.array(medium_data)

    high_data = []
    for result in vulnerability_result:
        high_data.append(result[3])
    high_data = np.array(high_data)

    critical_data = []
    for result in vulnerability_result:
        critical_data.append(result[4])
    critical_data = np.array(critical_data)


    # now some magic to create the graph
    y_pos = np.arange(len(all_servers))
    fig = plt.figure(figsize = (10, 10), frameon = False)
    ax = fig.add_subplot(111)

    # TODO: emtpy bars dont need ax.text

    # critical data
    # create a red horizontal bar from the array high_data for each host and add the number to it
    bar_critical = ax.barh(y_pos, critical_data, color = 'red')
    rects = bar_critical.patches
    for rect, label in zip(rects, critical_data):
        height = rect.get_height()
        if label != 0:
            ax.text(rect.get_x() + rect.get_width() / 2, rect.get_y(), label, color = 'black', ha = 'center', va = 'bottom')

    # high data
    # create an orange horizontal bar from the array high_data for each host and add the number to it
    bar_high = ax.barh(y_pos, high_data, color = '#EE9336', left = critical_data)
    rects = bar_high.patches
    for rect, label in zip(rects, high_data):
        height = rect.get_height()
        if label != 0:
           ax.text(rect.get_x() + rect.get_width() / 2, rect.get_y(), label, color = 'black', ha = 'center', va = 'bottom')

    # medium data
    # create a magenta horizontal bar from the array medium_data for each host and add the number to it
    bar_medium = ax.barh(y_pos, medium_data, color = 'yellow', left = critical_data + high_data)
    rects = bar_medium.patches
    for rect, label in zip(rects, medium_data):
        height = rect.get_height()
        if label != 0:
            ax.text(rect.get_x() + rect.get_width() / 2, rect.get_y(), label, color = 'black', ha = 'center', va = 'bottom')

    # low data
    # create a green horizontal bar from the array low_data for each host and add the number to it
    bar_low = ax.barh(y_pos, low_data, color = 'green',left = medium_data + critical_data + high_data)
    rects = bar_low.patches
    for rect, label in zip(rects, low_data):
        height = rect.get_height()
        if label != 0:
            ax.text(rect.get_x() + rect.get_width() / 2, rect.get_y(), label, color = 'black', ha = 'center', va = 'bottom')

    # add info about the graph, and save it
    ax.set_title(export_file)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(all_servers)
    plt.savefig(args_dir + '/' + export_file.replace(' ', '_') + '_vuln_hbar.'+ args_format)


#make an average piechart from compliance_result into export_file. the args_format is the fileformat of export_file
def make_comp_avg_piechart(compliance_result, export_file, args_format, args_dir):

    #calculate average passed, warning, failed
    server_count = len (compliance_result)

    all_passed = 0
    for result in compliance_result:
        all_passed += result[1]

    all_warning = 0
    for result in compliance_result:
        all_warning += result[2]

    all_failed = 0
    for result in compliance_result:
        all_failed += result[3]

    total_items = (all_passed + all_warning + all_failed) / server_count
    avg_passed = round(float(all_passed / server_count) / total_items*100,2)
    avg_warning = round(float(all_warning / server_count) / total_items*100,2)
    avg_failed = round(float(all_failed / server_count) / total_items*100,2)

    #now, lets make the piechart!
    labels = 'Passed', 'Warning', 'Failed'
    colors = ["green", "magenta","red"]
    sizes = [avg_passed, avg_warning, avg_failed]

    fig = plt.figure(figsize = (10, 10), frameon = False)
    ax = fig.add_subplot(111)
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')
    ax.set_title(export_file + " - total avg")
    plt.savefig(args_dir + '/' + export_file.replace(' ', '_') + '_comp_pie.'+ args_format)


#make a horizontal barchart from compliance_result into export_file. the args_format is the fileformat of export_file
def make_comp_hbarchart(compliance_result,export_file,args_format, args_dir):
    all_servers = []
    # x items do not change through this
    for result in compliance_result:
        all_servers.append(result[0])

    passed_data = []
    for result in compliance_result:
        passed_data.append(result[1])
    passed_data = np.array(passed_data) #needs to be array to use the correct positioning in ax.barh left=

    warning_data = []
    for result in compliance_result:
        warning_data.append(result[2])
    warning_data = np.array(warning_data)

    failed_data = []
    for result in compliance_result:
        failed_data.append(result[3])
    failed_data = np.array(failed_data)

    # now some magic to create the graph
    y_pos = np.arange(len(all_servers))
    fig = plt.figure(figsize = (10, 10), frameon = False)
    ax = fig.add_subplot(111)

    # TODO: emtpy bars dont need ax.text

    # passed data
    # create a green horizontal bar from the array passed_data for each host and add the number to it
    bar_passed = ax.barh(y_pos, passed_data, color = 'g')
    rects = bar_passed.patches
    for rect, label in zip(rects, passed_data):
        height = rect.get_height()
        if label != 0:
            ax.text(rect.get_x() + rect.get_width() / 2 + 2, rect.get_y(), label, color = 'black', ha = 'center', va = 'bottom')

    # warning data
    # create a magenta horizontal bar from the array warning_data for each host and add the number to it
    bar_warning = ax.barh(y_pos, warning_data, color = 'm', left = passed_data)
    rects = bar_warning.patches
    for rect, label in zip(rects, warning_data):
        height = rect.get_height()
        if label != 0:
            ax.text(rect.get_x() + rect.get_width() / 2, rect.get_y(), label, color = 'black', ha = 'center', va = 'bottom')

    # failed data
    # create a red horizontal bar from teh array failed_data for each host and add the number to it
    bar_failed = ax.barh(y_pos, failed_data, color = 'r', left = warning_data + passed_data)
    rects = bar_failed.patches
    for rect, label in zip(rects, failed_data):
        height = rect.get_height()
        if label != 0:
            ax.text(rect.get_x() + rect.get_width() / 2, rect.get_y(), label, color = 'black', ha = 'center', va = 'bottom')

    # add info about the graph, and save it
    ax.set_title(export_file)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(all_servers)
    plt.savefig(args_dir + '/' + export_file.replace(' ', '_') + '_comp_hbar.'+ args_format)

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

def main():
    parser = argparse.ArgumentParser(description = 'Create a graphic horizontal barchart from a Nessus compliance scan input file.')
    parser.add_argument('-i', '--input', help = 'Input file in .nessus format',
        default = None)
    parser.add_argument('-f', '--format', help = 'Export file format', choices = ['png', 'pdf', 'ps', 'eps', 'svg'],
        default = 'png')
    parser.add_argument('-n', '--name', help = 'Export file name. Default is Report name',
        default = None)
    parser.add_argument('-d', '--dir', help = 'Export file directory',
        default = '.')
    parser.add_argument('-t', '--type', help = 'What type of result to parse the file for.', choices = ['both', 'vulnerability','compliance' ],
        default = 'both')
    args = parser.parse_args()

    if not args.input:
        print('Need input file. Specify one with -i')
        sys.exit(1)

    if os.access(args.dir, os.W_OK) == False:
        print "Directory does not exist, or we cannot write in it!"
        sys.exit(1)

    # read the file..might be big though...
    try:
        f = open(args.input, 'r')
    except:
        print 'File %s not found!' % args.input
        sys.exit(1)

    print 'Parsing file %s as xml into memory, hold on...' % (args.input)

    nessus_xml_data = BeautifulSoup(f.read(), 'lxml')

    # set the output filename
    if not args.name:
        repname = nessus_xml_data.report['name']
        if len(repname) > 0:
            export_file = repname
            print 'Valid policy found %s' % (export_file)
        else:
            print 'Didn\'t find any valid policyname in the file. Are you sure this is a valid nessus file?'
            sys.exit(1)
    else:
        export_file = args.name

    # see if there are any hosts that are reported on
    hosts = nessus_xml_data.findAll('reporthost')
    if len(hosts) == 0:
        print 'Didn\'t find any hosts in file. Is this a valid nessus file?'
        sys.exit(1)
    else:
        print 'Found %i hosts' % (len(hosts))

    print 'Magically making images %s' % (export_file.replace(' ', '_') + '.' + args.format)

    if args.type == "both" or args.type == "compliance":
        #ok now that we have the compliance results, lets make some magic!
        compliance_result = []
        compliance_result = parse_comp_results(hosts)
        if len(compliance_result) > 0:
            print "Saving compliance graphic files to directory: %s" % (args.dir)
            make_comp_hbarchart(compliance_result,export_file, args.format, args.dir)
            make_comp_avg_piechart(compliance_result, export_file, args.format, args.dir)
        else:
            print "Did not find any compliance items, not making output files\n"

    if args.type == "both" or args.type == "vulnerability":
        vulnerability_result = []
        vulnerability_result = parse_vuln_results(hosts)
        if len(vulnerability_result) >0:
            print "Saving vulnerability graphic files to directory: %s" % (args.dir)
            make_vuln_avg_piechart(vulnerability_result, export_file, args.format, args.dir)
            make_vuln_hbarchart(vulnerability_result, export_file, args.format, args.dir)
        else:
            print "Did not find any vulnerability items, not making output files\n"

if __name__ == "__main__":
  main()

