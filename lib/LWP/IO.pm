package LWP::IO;

# $Id: IO.pm,v 1.2 1995/09/04 18:39:51 aas Exp $

require LWP::Debug;

=head1 NAME

LWP::IO - Low level I/O capability

=head1 DESCRIPTION

=head2 LWP::IO::read($fd, $data, $size, $offset, $timeout)

=head2 LWP::IO::write($fd, $data, $timeout)

These routines provide low level I/O with timeout capability for the
LWP library.  These routines will only be installed if they are not
already defined.  This fact can be used by programs that need to
override these functions.  Just provide replacement functions before
you require LWP. See also L<LWP::TkIO>.

=cut

my $read = <<'EOT';

sub read
{
    my $fd      = shift;
    # data is now $_[0]
    my $size    = $_[1];
    my $offset  = $_[2] || 0;
    my $timeout = $_[3];

    my $rin = '';
    vec($rin, fileno($fd), 1) = 1;
    my $nfound = select($rin, undef, undef, $timeout);
    if ($nfound == 0) {
	die "Timeout";
    } elsif ($nfound < 0) {
	die "Select failed: $!";
    } else {
	my $n = sysread($fd, $_[0], $size, $offset);
	LWP::Debug::conns("Read $n bytes: '$_[0]'") if defined $n;
	return $n;
    }
}
EOT


my $write = <<'EOT';

sub write
{
    my $fd = shift;
    my $timeout = $_[1];  # we don't want to copy data in $_[0]

    my $len = length $_[0];
    my $offset = 0;
    while ($offset < $len) {
	my $win = '';
	vec($win, fileno($fd), 1) = 1;
	my $nfound = select(undef, $win, undef, $timeout);
	if ($nfound == 0) {
	    die "Timeout";
	    #return $bytes_written;
	} elsif ($nfound < 0) {
	    die "Select failed: $!";
	} else {
	    my $n = syswrite($fd, $_[0], $len-$offset, $offset);
	    return $bytes_written unless defined $n;
	    LWP::Debug::conns("Write $n bytes: '" .
			      substr($_[0], $offset, $n) .
			      "'");
	    $offset += $n;
	}
    }
    $offset;
}

EOT


eval $read  unless defined &read;  die "LWP::IO::read $@" if $@;
eval $write unless defined &write; die "LWP::IO::write $@" if $@;

1;