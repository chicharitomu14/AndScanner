#!/usr/bin/perl
#########################################################################################
#
#   File	  : splitupdate
#   Description   : Unpack a Huawei X2 'UPDATE.APP' file.
#
#   Last Modified : Thu 24 December 2009
#   By	    : McSpoon
#
#   Last Modified : Wed 18 June 2010
#   By	    : ZeBadger (z e b a d g e r @ h o t m a i l . c o m)
#   Comment       : Added filename selection
#
#   Last Modified : Wed 19 June 2010
#   By	    : ZeBadger (z e b a d g e r @ h o t m a i l . c o m)
#   Comment       : Added CRC checking
#
#   Last Modified : Sat 20 February 2016
#   By	    : Marco Minetti (m a r c o . m i n e t t i @ n o v e t i c a . o r g)
#   Comment       : Added filename autodetection and improved logging
#
#########################################################################################
 
use strict;
use warnings;

my $CRC_CHECK= -e "crc" && -x _;

# Turn on print flushing.
$|++;
 
# Unsigned integers are 4 bytes.
use constant UINT_SIZE => 4;
 
# If a filename wasn't specified on the commmand line then
# assume the file to be unpacked is under current directory. 
my $FILENAME = undef;
my $matching = '.';
if (@ARGV) {
	$FILENAME = $ARGV[0];
  if (scalar(@ARGV) >= 3) {
    $matching = $ARGV[2];
  }
}
 
open(INFILE, $FILENAME) or die "Cannot open $FILENAME: $!\n";
binmode INFILE;
 
# Skip the first 92 bytes, they're blank.
#seek(INFILE, 92, 0);
 
# We'll dump the files into a folder called "output".
my $fileLoc=0;
my $BASEPATH = "$ARGV[1]/";
mkdir $BASEPATH;

while (!eof(INFILE))
{
	$fileLoc=&find_next_file($fileLoc);
	#printf "fileLoc=%x\n",$fileLoc;
	seek(INFILE, $fileLoc, 0);
	$fileLoc=&dump_file($matching);
}

close INFILE;
 

# Find the next file block in the main file
sub find_next_file
{
	my ($_fileLoc) = @_;
	my $_buffer = undef;
	my $_skipped=0;

	read(INFILE, $_buffer, UINT_SIZE);
	while ($_buffer ne "\x55\xAA\x5A\xA5" && !eof(INFILE))
	{
		read(INFILE, $_buffer, UINT_SIZE);
		$_skipped+=UINT_SIZE;
	}

	return($_fileLoc + $_skipped);
}
 
# Unpack a file block and output the payload to a file.
sub dump_file {
    my $buffer = undef;
    my $calculatedCRC = undef;
    my $sourceCRC = undef;
    my $matching = $_[0];
    
    # Verify the identifier matches.
    read(INFILE, $buffer, UINT_SIZE); # HeaderId
    unless ($buffer eq "\x55\xAA\x5A\xA5") { die "Unrecognised file format. Wrong identifier.\n"; }
    read(INFILE, $buffer, UINT_SIZE); # HeaderLength
    my ($headerLength) = unpack("V", $buffer);
    read(INFILE, $buffer, 4);	 # Unknown1
    read(INFILE, $buffer, 8);	 # HardwareID
    my ($hardwareId) = unpack("A8", $buffer);
    read(INFILE, $buffer, 4);	# FileSequence
    my ($fileSeq) = $buffer;
    read(INFILE, $buffer, UINT_SIZE); # FileSize
    my ($dataLength) = unpack("V", $buffer);
    my ($fileSize) = prettyBytes($dataLength);
    read(INFILE, $buffer, 16);	# FileDate
    my ($fileDate) = unpack("Z16", $buffer);
    read(INFILE, $buffer, 16);	# FileTime
    my ($fileTime) = unpack("Z16", $buffer);
    read(INFILE, $buffer, 16);	# FileType
    my ($fileType) = unpack("Z16", $buffer);
    read(INFILE, $buffer, 16);	# Blank1
    read(INFILE, $buffer, 2);	 # HeaderChecksum
    read(INFILE, $buffer, 2);	 # BlockSize
    read(INFILE, $buffer, 2);	 # Blank2

    # Grab the checksum of the file
    read(INFILE, $buffer, $headerLength-98);
    $sourceCRC=slimhexdump($buffer);
    
    my ($fileName) = "$fileType" . ".img";
    if ($fileName =~ /$matching/) {
      print "extracting $fileName ($fileSize)...";
    
      # Dump the payload.
      read(INFILE, $buffer, $dataLength);
      open(OUTFILE, ">$BASEPATH$fileName") or die "Unable to create $fileName: $!\n";
      binmode OUTFILE;
      print OUTFILE $buffer;
      close OUTFILE;

		  print "\r";
		  print "verifying checksum for $fileType ($fileSize)...";

      $calculatedCRC=`./crc $BASEPATH$fileType.img` if $CRC_CHECK;
      chomp($calculatedCRC) if $CRC_CHECK;

		  print "\r";
      printf "%*v2.2X", '', $fileSeq;
      if($CRC_CHECK){
			  if (!$calculatedCRC eq $sourceCRC)
			  {
				  print " - !!! CRC ERROR";
			  }
      }
    }
    else {
      seek(INFILE, $dataLength, 1);
    }
    print " $fileType $fileSize $fileDate $fileTime";
    
    print "\n";
    
    # Ensure we finish on a 4 byte boundary alignment.
    my $remainder = UINT_SIZE - (tell(INFILE) % UINT_SIZE);
    if ($remainder < UINT_SIZE) {
    	# We can ignore the remaining padding.
    	read(INFILE, $buffer, $remainder);
    }
    
    return (tell(INFILE));
}

sub hexdump ()
{
	my $num=0;
	my $i;
	my $rhs;
	my $lhs;
	my ($buf) = @_;
	my $ret_str="";

	foreach $i ($buf =~ m/./gs)
	{
		# This loop is to process each character at a time.
		#
		$lhs .= sprintf(" %02X",ord($i));

		if ($i =~ m/[ -~]/)
		{
			$rhs .= $i;
		}
		else
		{
			$rhs .= ".";
		}

		$num++;
		if (($num % 16) == 0)
		{
			$ret_str.=sprintf("%-50s %s\n",$lhs,$rhs);
			$lhs="";
			$rhs="";
		}
	}
	if (($num % 16) != 0)
	{
		$ret_str.=sprintf("%-50s %s\n",$lhs,$rhs);
	}

	return ($ret_str);
}
	
sub slimhexdump ()
{
	my $i;
	my ($buf) = @_;
	my $ret_str="";

	foreach $i ($buf =~ m/./gs)
	{
		# This loop is to process each character at a time.
		#
		$ret_str .= sprintf("%02X",ord($i));
	}

	return ($ret_str);
}

sub prettyBytes {
	my $size = $_[0];
	
	foreach ('B','KB','MB','GB','TB','PB')
	{
		return sprintf("%.2f",$size)."$_" if $size < 1024;
		$size /= 1024;
	}
	
}
