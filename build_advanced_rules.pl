#!/usr/bin/perl

## Build custom rules for SNORT IDS
## Built and tested for SecurityOnion and Pulledpork
## giovanni.mellini@gmail.com

# Copyright (C) 2015 Giovanni Mellini

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

use strict;
use warnings;
use File::Copy;
use Getopt::Long qw(:config no_ignore_case bundling);
use Carp;

### Vars here

# version
my $VERSION = "Build Advanced Rules for SNORT IDS v0.1";
# verbose, default off - set with -v option
my $Verbose = 0;
# Test mode, default off - set with -t option
my $TestMode = 0;

# Vars to fetch config values from pulledpork.conf file
my ($Config_file);
my ($Config_key);
my %Config_info = ();
undef %Config_info;

# Downloaded rules file
my $DownloadedRules_file;
my $ModifiedDownloadedRules_file;

# sid-msg.map file
my $sid_msg_map;
my $sid_msg_map_tmp;
my $sid_msg_version;
my %sid_msg_map;
my %sid_msg_hash = ();
undef %sid_msg_map;
undef %sid_msg_hash;

# Local Advanced Rules file
my $LocalAdvancedRules_file;

###
### BEGIN Configs
###
# Custom SID format:
# <$Rule_prepend><%Rules_hash index><OLD SID - 8 digits, add leading zeros if length -lt 8>
my $Rule_prepend=9;
# Rules hash to store regexp and transform
my %Rules_hash = ();
undef %Rules_hash;
#
# BEGIN Rules
# Note that the {'to'} field of the transform don't need chars to be escaped (unlike the {'from'} field).
# Following chars of the {'to'} field don't need to be escaped: [ ] (
#
# index 0
# outside TCP services
$Rules_hash{0}{'regexp'} = 'tcp \[[0-9.,/]*\] any \-> \$HOME_NET any.* threshold:.* classtype:misc-attack;.* sid:(2[0-9]{6});';
$Rules_hash{0}{'transform'}{0}{'from'} = '\$HOME_NET any ';
$Rules_hash{0}{'transform'}{0}{'to'} = '[192.168.0.1] [443,5555] ';
$Rules_hash{0}{'transform'}{1}{'from'} = '\(msg:"';
$Rules_hash{0}{'transform'}{1}{'to'} = '(msg:"NEW RULE - ';
# index 1
# outside UDP service
$Rules_hash{1}{'regexp'} = 'udp \[[0-9.,/]*\] any \-> \$HOME_NET any.* threshold:.* classtype:misc-attack;.* sid:(2[0-9]{6});';
$Rules_hash{1}{'transform'}{0}{'from'} = '\$HOME_NET any ';
$Rules_hash{1}{'transform'}{0}{'to'} = '[192.168.0.2] [12345] ';
$Rules_hash{1}{'transform'}{1}{'from'} = '\(msg:"';
$Rules_hash{1}{'transform'}{1}{'to'} = '(msg:"NEW RULE - ';
#
# END Rules
#
###
### END Configs
###

### Subroutines here

## Help routine.. display help to stdout then exit
sub Help {
    my $msg = shift;
    if ($msg) { print "\nERROR: $msg\n"; }

    print <<__EOT;
  Usage: $0 [-tVv?h] [-d <downloaded.rules file path>] -c <pulledpork.conf file path>
  
   Options:
   -? Print this help.
   -h Print this help.
   -c Where the pulledpork.conf config file lives. This is mandatory.
   -d Where the downloaded.rules file lives. If not set, read in pulledpork.conf file (rule_path option).
   -t TEST MODE. Write all the result files in /tmp/ directory without modify any file.
   -V Print version and exit.
   -v Verbose mode for troubleshooting.

   Note: The script saves the new local rules in a file named local.advanced.rules
         In this file a comment (#### at the beginning of the rule) is added to the original rules (the one in downloaded.rules file)
          if the rule match one of the regular expressions.
         The local.advanced.rules full path shall be set in pulledpork.conf (local_rules var) so new defined rules are loaded.
         If not set, local.advanced.rules file is saved in the same dir of downloaded.rules file.

   Note: In test mode (-t) the downloaded.rules.modified and local.advanced.rules temporary files can be found in /tmp/ directory.
         The original downloaded.rules and sid-msg.map files are not modified.

__EOT

    exit(0);
}

## uh, yeah
sub Version {
    print("$VERSION\n\n");
    exit(0);
}

## routine to grab our config from the defined config file
sub parse_config_file {
    my ( $FileConf, $Config_val ) = @_;
    my ( $config_line, $Name, $Value );

    if ( !open( CONFIG, "$FileConf" ) ) {
        print "ERROR: Config file not found : $FileConf\n";
        exit(1);
    }
    open( CONFIG, "$FileConf" );
    while (<CONFIG>) {
        $config_line = $_;
        chomp($config_line);
        $config_line = trim($config_line);
        if ( ( $config_line !~ /^#/ ) && ( $config_line ne "" ) ) {
            ( $Name, $Value ) = split( /=/, $config_line );
            if ( $Value =~ /,/ && $Name eq "rule_url" ) {
                push( @{ $$Config_val{$Name} }, split( /,/, $Value ) );
            }
            elsif ( $Name eq "rule_url" ) {
                push( @{ $$Config_val{$Name} }, split( /,/, $Value ) )
                  if $Value;
            }
            else {
                $$Config_val{$Name} = $Value;
            }
        }
    }
    close(CONFIG);
}

## This process downloaded.rules file and replaces the identified rules with new ones
sub read_rules_and_customize {
    my ( $path, $modified_path, $advanced_path ) = @_;
    my ( $rule_new, $sid_new, $sid_orig, $sid_orig_plus);
    my ( @elements ); 
    if ( -f $path ) {
        open( DATA, "$path" ) || croak "ERROR: Couldn't read $path - $!\n";
        print "INFO: Reading rules file...\n" if ( $Verbose );
        @elements = <DATA>;
        close(DATA);

        # open files for write
        open ( WRITE, '>', $modified_path ) || croak ("ERROR: Unable to open $modified_path for writing! - $!\n");
        print "INFO: Writing modified rules file...\n" if ( $Verbose );
        open ( WRITE2, '>', $advanced_path ) || croak ("ERROR: Unable to open $advanced_path for writing! - $!\n");
        print "INFO: Writing Advanced Rules file...\n" if ( $Verbose );

        foreach my $rule (@elements) {
            # skip commented rules
            if ( $rule =~ /^#/ ) {
                    print WRITE "$rule";
            } else {
                my $match_found = 0;
                # try to match rules regexp
                foreach my $Rules_hash_index ( sort keys %Rules_hash ) {
                    if ( $rule =~ /$Rules_hash{$Rules_hash_index}{'regexp'}/ ) {
                        print "---\nRule: ".$rule if ( $Verbose );
                        $match_found = 1;
			if ( $Rules_hash{$Rules_hash_index}{'disabled'} && $Rules_hash{$Rules_hash_index}{'disabled'} == 1 ) { #to disable
                                print "DISABLED rule\n" if ( $Verbose );
                        } else { # transform
                                # get original rule SID
                                $rule =~ /ssid:(.*);/;
                                #$sid_orig = $1;
                                # the original SID must have at least 7 digits; if not, add 0s
                                $sid_orig = $1;
                                print "SID: ".$sid_orig."\n" if ( $Verbose );
                                # build the new SID 
                                # <$Rule_prepend><%Rules_hash index><OLD SID up to 8 numbers>
                                $sid_orig_plus = sprintf ( "%07d", $1);
                                $sid_new = "sid:".$Rule_prepend.$Rules_hash_index.$sid_orig_plus.";";
                                print "\$Rules_hash INDEX: ".$Rules_hash_index."\n" if ( $Verbose );
                                print "NEW SID: ".$sid_new."\n" if ( $Verbose );
                                $rule_new = $rule;
                                # loop through transform rules
                                #foreach my $Rules_hash_transform ( keys $Rules_hash{$Rules_hash_index}{'transform'} ) {
                                foreach my $Rules_hash_transform ( keys %{ $Rules_hash{$Rules_hash_index}{'transform'} } ) {
                                    print "Transform FROM: ".$Rules_hash{$Rules_hash_index}{'transform'}{$Rules_hash_transform}{'from'}."\n" if ( $Verbose );
                                    print "Transfrom TO: ".$Rules_hash{$Rules_hash_index}{'transform'}{$Rules_hash_transform}{'to'}."\n" if ( $Verbose );
                                    $rule_new =~ s/$Rules_hash{$Rules_hash_index}{'transform'}{$Rules_hash_transform}{'from'}/$Rules_hash{$Rules_hash_index}{'transform'}{$Rules_hash_transform}{'to'}/;
                                }
                                # finally transform SID
                                print "Transfrom SID: from -> sid:".$sid_orig."; to -> ".$sid_new."\n" if ( $Verbose );
                                $rule_new =~ s/sid:$sid_orig;/$sid_new/;
                                # write the new rule 
                                print WRITE2 $rule_new;
                                print "New Rule: ".$rule_new if ( $Verbose );
                        }
                    } #end if $rule=~
                } #end foreach

                if ( $match_found == 1 ) {
                    # there is at least 1 match for current rule
                    # proceed with disabling putting #### at the beginning of the rule
                    print WRITE "####".$rule;
                    # to reference original rule in local.advanced.rules file
                    print WRITE2 "####".$rule;
                    print "---\n####".$rule if ( $Verbose );
                } else {
                    print WRITE $rule;
                }
            }
        }
    }
    undef @elements;
    close(WRITE);
    close(WRITE2);
}

## read rules file
sub read_rules {
    my ( $hashref, $path, ) = @_;
    my ( $sid, $gid, @elements );
    print "\nReading rules file: ".$path."...\n" if ( $Verbose );
    
    if ( -f $path ) {
        open( DATA, "$path" ) || croak "Couldn't read $path - $!";
        @elements = <DATA>;
        close(DATA);

        foreach my $rule (@elements) {
            if ( $rule =~ /^\s*#*\s*(alert|drop|pass)/i ) {
                if ( $rule =~ /sid:\s*\d+/ ) {
                    $sid = $&;
                    $sid =~ s/sid:\s*//;
                    if ( $rule =~ /gid:\s*\d+/i ) {
                        $gid = $&;
                        $gid =~ s/gid:\s*//;
                    }
                    else { $gid = 1; }
                    if ( $rule =~ /flowbits:\s*((un)?set(x)?|toggle)/ ) {
                        my ( $header, $options ) = split( /^[^"]* \(/, $rule );
                        my @optarray = split( /(?<!\\);(\t|\s)*/, $options )
                          if $options;
                        foreach my $option ( reverse(@optarray) ) {
                            my ( $kw, $arg ) = split( /:/, $option ) if $option;
                            next unless ( $kw && $arg && $kw eq "flowbits" );
                            my ( $flowact, $flowbit ) = split( /,/, $arg );
                            next unless $flowact =~ /^\s*((un)?set(x)?|toggle)/i;
                            $$hashref{ trim($gid) }{ trim($sid) }
                              { trim($flowbit) } = 1;
                        }
                    }
                    $$hashref{ trim($gid) }{ trim($sid) }{'rule'} = $rule;
		    print "gid=".trim($gid).",sid=".trim($sid).",rule=".$rule if ( $Verbose );
                }
            }
        }
    }
    undef @elements;
}

## make the sid-msg.map hash
sub sid_msg {
    my ( $ruleshash, $sidhash, $enonly ) = @_;
    my ( $gid, $arg, $msg );
    print "\nGenerating sid-msg.map hash...\n" if ( $Verbose );
    foreach my $k ( sort keys %$ruleshash ) {
        foreach my $k2 ( sort keys %{ $$ruleshash{$k} } ) {
	    next if ((defined $enonly) && $$ruleshash{$k}{$k2}{'rule'} !~ /^\s*(alert|drop|pass)/);
            ( my $header, my $options ) =
              split( /^[^"]* \(\s*/, $$ruleshash{$k}{$k2}{'rule'} )
              if defined $$ruleshash{$k}{$k2}{'rule'};
            my @optarray = split( /(?<!\\);\s*/, $options ) if $options;
            foreach my $option ( reverse(@optarray) ) {
                my ( $kw, $arg ) = split( /:\s*/, $option ) if $option;
		my $gid = $k;
		$gid = 1 if $k == 0;
		next unless ($kw && $arg && $kw =~ /(reference|msg|rev|classtype|priority)/);
		print "> GID: ".$gid." SID: ".$k2."\n" if ( $Verbose );
		if ( $kw eq "reference" ) {
                    push( @{ $$sidhash{$gid}{$k2}{refs} }, trim($arg));
		    print ">> reference: ".trim($arg)."\n" if ( $Verbose );
                } elsif ($kw eq "msg"){
		    $arg =~ s/"//g;
		    $$sidhash{$gid}{$k2}{msg} = trim($arg);
		    print ">> msg: ".trim($arg)."\n" if ( $Verbose );
		} elsif ($kw eq "rev"){
		    $$sidhash{$gid}{$k2}{rev} = trim($arg);
		    print ">> rev: ".trim($arg)."\n" if ( $Verbose );
		} elsif ($kw eq "classtype") {
		    $$sidhash{$gid}{$k2}{classtype} = trim($arg);
		    print ">> classtype: ".trim($arg)."\n" if ( $Verbose );
		} elsif ($kw eq "priority") {
		    $$sidhash{$gid}{$k2}{priority} = trim($arg);
		    print ">> priority: ".trim($arg)."\n" if ( $Verbose );
		}
            }
        }
    }
}

## sid file time!
sub sid_write {
    my ( $hashref, $file, $sid_msg_version ) = @_;
    print "Writing v$sid_msg_version $file temp file....\n" if ( $Verbose );
    open( SIDMSG, '>', $file ) || croak "Unable to write $file -$!";
    foreach my $k ( sort keys %$hashref ) {
		foreach my $k2 ( sort keys %{$$hashref{$k}}){
			print ">GID:".$k." SID:".$k2."\n" if ( $Verbose );
		    if ($sid_msg_version == 2){
				print SIDMSG "$k || $k2 || $hashref->{$k}{$k2}{rev} || ";
				print "$k || $k2 || $hashref->{$k}{$k2}{rev} || " if ( $Verbose );
				
				if ($hashref->{$k}{$k2}{classtype}) {
				    print SIDMSG "$hashref->{$k}{$k2}{classtype} || ";
				    print "$hashref->{$k}{$k2}{classtype} || " if ( $Verbose );
				}
				else { 
					print SIDMSG "NOCLASS || "; 
					print "NOCLASS || " if ( $Verbose );
				}

				if ($hashref->{$k}{$k2}{priority}) {
				    print SIDMSG "$hashref->{$k}{$k2}{priority} || ";
				    print "$hashref->{$k}{$k2}{priority} || " if ( $Verbose );
				}
				else { 
					print SIDMSG "0 || "; 
					print "0 || " if ( $Verbose );
				}
		    } else {
				print SIDMSG "$k2 || ";
				print "$k2 || " if ( $Verbose );
		    }

		    print SIDMSG "$hashref->{$k}{$k2}{msg}";
		    print "$hashref->{$k}{$k2}{msg}" if ( $Verbose );
		    foreach (@{$hashref->{$k}{$k2}{refs}}) {
				print SIDMSG " || $_";
				print " || $_" if ( $Verbose );
		    }
		    print SIDMSG "\n";
		    print "\n" if ( $Verbose );
		}
    }
    close(SIDMSG);
}

## Trim it up, loves the trim!
sub trim {
    my ($trimmer) = @_;
    if ($trimmer) {
        $trimmer =~ s/^\s*//;
        $trimmer =~ s/\s*$//;
        return $trimmer;
    }
}

###
### Main
###

if ( $#ARGV == -1 ) {
    Help( "Please use the right sintax" );
}

## Lets grab any runtime values and insert into our variables using getopt::long
GetOptions(
    "c=s"    => \$Config_file,
    "d=s"    => \$DownloadedRules_file,
    "t"      => \$TestMode,
    "V!"     => sub { Version() },
    "v+"     => \$Verbose,
    "help|h|?" => sub { Help() }
);

# Test mode alert
if ( $TestMode ) {
    print "=================\n";
    print "=== TEST MODE ===\n";
    print "=================\n\n";
    print "Please note that the generated downloaded.rules.modified and local.advanced.rules files are written to /tmp/ directory.\nThe original downloaded.rules and sid-msg.map files are not modified.\n\n";
}

# Verify -c option
if ( !$Config_file ) { Help("No pulledpork.conf file specified"); }
print "INFO: Pulled Pork file: $Config_file\n";

# Call the subroutine to fetch pulledpork.conf config values
parse_config_file( $Config_file, \%Config_info );

# Get sid-msg.map file from pulledpork.conf
$sid_msg_map = ( $Config_info{'sid_msg'} );
if ( !$sid_msg_map ) { Help("No sid-msg.map file specified in pulledpork.conf \(sid_msg var\)."); }
# Get sid-msg.map version
$sid_msg_version = $Config_info{'sid_msg_version'};
if ( !$sid_msg_version ) { Help("No sid-msg.map version specified in pulledpork.conf \(sid_msg_version var\).\nSpecify version 1 or 2 for sid_msg_version in your config file."); }
print "INFO: SID-MSG map file version found: ".$sid_msg_version."\n";

# Dump pulledpork.conf variables for verbose output
if ( $Verbose ) {
    print "INFO: Key sets from $Config_file file:\n";
    foreach $Config_key ( keys %Config_info ) {
        if ( $Config_info{$Config_key} ) {
            print "> $Config_key = $Config_info{$Config_key}\n";
        }
    }
    print "\n";
}

# Verify dowloaded.rules is ok, first not is passed via command line check for pulledpork.conf
if ( !$DownloadedRules_file ) { 
    if ( !$Config_info{'rule_path'} ) { 
        Help("No downloaded.rules found in pulledpork.conf"); 
        } else {
            $DownloadedRules_file=$Config_info{'rule_path'};
        }
}

print "INFO: Downloaded Rules file: $DownloadedRules_file\n";

# Verify that local.advanced.rules file is set in pulledpork.conf, otherwise alert
my @local_rules_path = split( /,/, $Config_info{'local_rules'} );
my $advanced_found = 0;
foreach ( @local_rules_path ) {
    if ( $_ =~ /local.advanced.rules$/ ) {
        $LocalAdvancedRules_file = $_;
        $advanced_found = 1;
    }
}
if ( !$advanced_found ) {
    # save to the same dir  of current downloaded.rules file
    $LocalAdvancedRules_file = $DownloadedRules_file;
    $LocalAdvancedRules_file =~ s/downloaded\.rules/local.advanced.rules/;
    print "WARNING: No local.advanced.rules file found in pulledpork.conf local_rules var.\n";
}

# set the right path for output files
if ( $TestMode ) {
    # in /tmp/ dir if in Test Mode
    $ModifiedDownloadedRules_file = "/tmp/downloaded.rules.modified";
    $LocalAdvancedRules_file = "/tmp/local.advanced.rules";
} else {
    # Set downloaded.rules.modified path in the same dir of downloaded.rules file
    $ModifiedDownloadedRules_file = $DownloadedRules_file.".modified";
}

# Read dowloaded.rules file and transform it based on current rules
read_rules_and_customize( $DownloadedRules_file, $ModifiedDownloadedRules_file, $LocalAdvancedRules_file);
print "INFO: Advanced Rules file written: $LocalAdvancedRules_file\n";
print "INFO: Full downloaded.rules file written: $ModifiedDownloadedRules_file\n";

# Create temp sid-msg.map for new rules
$sid_msg_map_tmp = "/tmp/sid-msg.map";
read_rules( \%sid_msg_hash, $LocalAdvancedRules_file );
sid_msg( \%sid_msg_hash, \%sid_msg_map, 0 );
sid_write( \%sid_msg_map, $sid_msg_map_tmp, $sid_msg_version );
print "INFO: sid-msg.map file for _NEW_ Rules only written: $sid_msg_map_tmp\n";

# Finally backup downloaded.rules file and copy the new one if:
# - not in test mode
# - local.advanced.rules file is defined in pulledpork.conf
# otherwise just save the new files.
if ( !$TestMode && $advanced_found ) {
    # update donwloaded.rules and write local.advanced.rules file
    copy( $DownloadedRules_file, $DownloadedRules_file.".backup" ) or croak "ERROR: Couldn't backup $DownloadedRules_file file - $!\n";
    print "INFO: Copied ".$DownloadedRules_file." to ".$DownloadedRules_file.".backup file for backup\n";
    move( $ModifiedDownloadedRules_file, $DownloadedRules_file ) or croak "ERROR: Couldn't copy $ModifiedDownloadedRules_file in $DownloadedRules_file - $!\n";
    print "INFO: Moved ".$ModifiedDownloadedRules_file." to ".$DownloadedRules_file." file\n";
    # update sid-msg.map file, append /tmp/sid-msg.map to original sid-msg.map
    copy( $sid_msg_map, $sid_msg_map.".backup" ) or croak "ERROR: Couldn't backup $sid_msg_map file - $!\n";
    print "INFO: Copied ".$sid_msg_map." to ".$sid_msg_map.".backup file for backup\n";
    open my $dest_file, '>>', $sid_msg_map or croak "ERROR: Couldn't open $sid_msg_map file for append - $!\n";
    open my $new_file, '<', $sid_msg_map_tmp or croak "ERROR: Couldn't open $sid_msg_map_tmp file for reading - $!\n";
    while ( my $line = readline ( $new_file ) ) { print $dest_file $line; }
    close $new_file;
    close $dest_file;
    print "INFO: Generated new ".$sid_msg_map."\n";
}

print "INFO: Script ended\n";
# At the end...
exit (0);
