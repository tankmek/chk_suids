#!/usr/bin/perl -w

 ;#
 ;# fakelabs development
 ;#

# file: chk_suid
# purpose: helps maintain suid/sgid integrity
# author: Michael Edie
#
# This program released under the same
# terms as perl itself
#

use strict;
use Digest::MD5;
use IO::File; 
use diagnostics;        # remove after release
use Fcntl qw(:flock);
use POSIX qw(strftime);

use constant DEBUG => 0;

# Global variables :\
my @suids;
my $count;

my $suidslist = (getpwuid($<))[7]."/suidslist";
my $suidsMD5  = (getpwuid($<))[7]."/suidsMD5";
my $masterMD5 = (getpwuid($<))[7]."/masterMD5";
 
autoflush STDOUT 1;

&splash;
sub splash{

    print "==============================\n",
          "       www.fakelabs.org       \n",
          "==============================\n",
          "                  chk_suids.pl\n",
          "++++++++++++++----------------\n";
}

opendir(ROOT,'/')
    || c_error("Could not open the root directory!");

print "[01] Generating system suid/guid list.\n";
&find_suids(*ROOT,'/');
sub find_suids{

    local (*P_FH) = shift;
    my $path = shift;
    my $content;

    opendir(P_FH,"$path")
      || c_error("Could not open $path");

    foreach $content (sort(readdir(P_FH))){
       next if $content eq '.' or $content eq '..';
       next if -l "$path$content";

       if (-f "$path$content"){
          push @suids,"$path$content"
             if (-u "$path$content" ||
                 -g "$path$content")  && ++$count;
       }

       elsif (-d "$path$content" && opendir(N_PATH,"$path$content")) {
           find_suids(*N_PATH,"$path$content/");
       }

       else { next; }
    }
}
print "[02] Found $count total suid/guid files on your system.\n";

print join "\n",@suids if DEBUG == 1;

&suids_perm;
sub suids_perm{

    my $wx_count = 0;
    my $ww_count = 0;
    my @wx_suids;
    my @ww_suids;
    my $tempfile = IO::File::new_tmpfile()
                     || c_error("Could not open temporary file");

    while(<@suids>){

        chomp;

        my ($user,$group) = (lstat)[4,5];
        my $mode = (lstat)[2] & 07777;

        $tempfile->printf("%-4o %-10s %-10s %-40s\n",
                   $mode,(getpwuid($user))[0],(getgrgid($group))[0],$_);
    }

    $tempfile->seek(0,0);

    foreach (<$tempfile>){
          my $perm = (split(/\s+/,$_))[0];
          if (($perm & 01) == 01){
            push @wx_suids,$_; ++$wx_count;
          }
          elsif (($perm & 02) == 00){
            push @ww_suids; ++$ww_count;
          }
    }

    @ww_suids = 'none' if !@ww_suids;
    @wx_suids = 'none' if !@wx_suids;

    print "[03] World writable suids found: $ww_count\n";
    print "=" x 50,"\n", @ww_suids, "=" x 10, "\n"
        if $ww_suids[0] !~/none/;

    print "[04] World executable suids found: $wx_count\n";
    print "=" x 50, "\n", @wx_suids, "=" x 50,"\n"
        if $wx_suids[0] !~/none/;

    cfg_check($tempfile);
}

sub cfg_check{

    my $tempfile = shift;
    my $lcount = 0;

print $masterMD5,$suidsMD5,$suidslist,"\n" if DEBUG == 1;

    foreach ($masterMD5,$suidsMD5,$suidslist){
          ++$lcount if !-e;
    }

    $0 =~s!.*/!!;

print $lcount,"\n" if DEBUG == 1;

    if (($lcount != 0) && ($lcount < 3)){
     print "[05] Inconsistency found with cfg files, exiting.\n";
    }

    elsif ($lcount == 3){
        print "[05] It seems this is your first time running $0.\n";

        &n_create($tempfile);
    }

    elsif ($lcount == 0){
        print "[05] Checking cfg and suid/guid integrity\n";
        sleep(2); 

        &c_suidlist($tempfile); &c_suidsmd5; &c_mastermd5;
    }
}

sub c_suidlist{
    
    my $tempfile = shift;
    my $slist = IO::File->new($suidslist, O_RDONLY)
                      || c_error("Could not open $suidslist for reading");
    
    flock($slist,LOCK_SH);

    $tempfile->seek(0,0);
    
    my %temp_vals;
    while(<$tempfile>){
        chomp;
        my ($tperm,$towner,$tgroup,$tfile) = split(/\s+/,$_,4);

print join ':',$tperm,$towner,$tgroup,$tfile,"\n" if DEBUG == 1;

        $temp_vals{$tfile}  = [$tperm,$towner,$tgroup,$tfile];
    }

    my %suid_vals;
    while(<$slist>){
        chomp;
        my ($sperm,$sowner,$sgroup,$sfile) = split(/\s+/,$_,4);

print join ':',$sperm,$sowner,$sgroup,$sfile,"\n" if DEBUG == 1;

        $suid_vals{$sfile} = [$sperm,$sowner,$sgroup,$sfile];
    }
    
    $slist->close;
    
    my $badsuids = 0;
    foreach my $val (sort keys %suid_vals){
          if ("@{$suid_vals{$val}}"  ne  "@{$temp_vals{$val}}"){

            ++$badsuids &&
            print "[06] !WARNING! suid/guid modification(s) found! \n",
                  "=" x 50,"\n" unless $badsuids;

            &suidl_warn(\@{$temp_vals{$val}},\@{$suid_vals{$val}});

          }
    }
    
    if (!$badsuids){
      print "[06] $suidslist: OK \n";
    } else {
         &f_badsuids;
    }
}

sub c_mastermd5{
    
    srand;

    my $tmd5f = POSIX::tmpnam();
    my $tsuf = (rand(time ^ $$)) + $<;

    $tmd5f .= $tsuf;

    c_error("[07] !WARNING! $tmd5f is a symlink, exiting") if -l $tmd5f;

    my $tempmd5 = IO::File->new($tmd5f, O_WRONLY|O_CREAT)
                || c_error("Could not open $tmd5f for writing");

    flock($tempmd5,LOCK_EX);

    my $mmd5f = IO::File->new($masterMD5, O_RDONLY)
                 || c_error("Could not open $masterMD5 for reading");

    flock($mmd5f,LOCK_SH); chomp(my $mmd5 = <$mmd5f>); $mmd5f->close;

    while(<@suids>){

        chomp;

        my ($md5f,$md5v) =  md5($_);

        $tempmd5->printf("%-40s: %-40s\n", $md5f, $md5v)
               if $md5f && $md5v;

    }  $tempmd5->close;

    my $s_md5 = md5($suidsMD5);
    my $t_md5 = md5($tmd5f);

    if (("$s_md5" eq "$t_md5") && ("$t_md5" eq "$mmd5")){
      print "[08] $masterMD5: OK \n";

    }
#    my $md5 = md5($suidsMD5); print "MASTER: $m_md5\n";
#    my $t_md5 = md5($tmd5); print "TEMP: $t_md5\n";
    
        
  print "[09] Verify this is actually your masterMD5 sum: $mmd5\n";
  sleep(3);

  &cleanup;
  &ret;
}

sub suidl_warn{

    my $tv_ref = shift;
    my $sv_ref = shift;

    printf("OLD: %-4d %-10s %-10s %-40s\n",
           $$tv_ref[0],$$tv_ref[1],$$tv_ref[2],$$tv_ref[3]);

    printf("NEW: %-4d %-10s %-10s %-40s\n",
           $$sv_ref[0],$$sv_ref[1],$$sv_ref[2],$$sv_ref[3]);

}

sub c_suidsmd5{
print "[07] $suidslist: OK \n";
}

sub cleanup{
print "[10] Cleaning up and exiting \n";
}

sub ret{
print "+=" x 28,"\n","s0ttle: $0 still in beta! :\\ \n";
}
#
# I was going to add the option to update the cfg files with any new legitimate 
# changes, but that would make it too easy for an intruder to circumvent this whole process
# its not too hard to do it manually anyway :\ 
#
sub f_badsuids{

    print "=" x 50,"\n","[07] Pay attention to any unknown changes shown above!\n";
    sleep(2);

}

sub n_create{

    my $tempfile = shift;
   
    print "[06] Creating: $suidslist\n"; &slst_create($tempfile);
    print "[07] Creating: $suidsMD5 \n"; &smd5_create;  
    print "[08] Creating: $masterMD5\n"; &mmd5_create;
}

sub slst_create{
   
    my $tempfile = shift;
    my $slist = IO::File->new($suidslist, O_WRONLY|O_CREAT)
                 || c_error("Could not open $suidslist for writing");

    flock($slist,LOCK_EX);

    $tempfile->seek(0,0);

    while(<$tempfile>){

        $slist->print("$_");
    }

    $tempfile->close; $slist->close;
}

sub smd5_create{
   
    my $smd5 = IO::File->new($suidsMD5, O_WRONLY|O_CREAT)
                || c_error("Could not open $suidsMD5 for writing");
    
    flock($smd5,LOCK_EX);

    while(<@suids>){

        chomp;

        my ($md5f,$md5v) =  md5($_);

        $smd5->printf("%-40s: %-40s\n", $md5f, $md5v)
               if $md5f && $md5v;
        
    }
    
    $smd5->close;
}

sub mmd5_create{
    
    my $mmd5v = (md5($suidsMD5))[1];
    my $mmd5 = IO::File->new($masterMD5, O_WRONLY|O_CREAT)
                || c_error("Could not open $masterMD5 for writing");
    
    flock($mmd5,LOCK_EX);

    $mmd5->print("$mmd5v\n");
    $mmd5->close;
}

sub md5{

    my $suid_file = shift;
    my %mdb;

    my $obj = Digest::MD5->new();

    if ( my $suidf = IO::File->new($suid_file, O_RDONLY) ){

      flock($suidf,LOCK_SH); binmode($suidf);
     
      $obj->addfile($suidf);
      $mdb{$suid_file} = $obj->hexdigest; 
      $obj->reset();
      $suidf->close;

      return($suid_file,$mdb{$suid_file});

    } else { warn("[E] Could not open $suid_file: $!\n");
    }
}

sub c_error{

    my $error = "@_";

    print "ERROR: $error: $!\n";
    exit(0);
}
