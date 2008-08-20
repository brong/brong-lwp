package LWP::Authen::Digest;
use strict;
use base 'LWP::Authen::Basic';

require Digest::MD5;
require URI;

# use the same logic as Basic to decide when to calculate the header

sub handles_request 
{
    my($class, $request, $auth_param, $base_url) = @_;

    my $host = $request->url->host_port;
    my $path = $request->url->path;

    # rfc2617 - domain
    # A quoted, space-separated list of URIs, as specified in RFC XURI
    # [7], that define the protection space.  If a URI is an abs_path, it
    # is relative to the canonical root URL (see section 1.2 above) of
    # the server being accessed. An absoluteURI in this list may refer to
    # a different server than the one being accessed. The client can use
    # this list to determine the set of URIs for which the same
    # authentication information may be sent: any URI that has a URI in
    # this list as a prefix (after both have been made absolute) may be
    # assumed to be in the same protection space. If this directive is
    # omitted or its value is empty, the client should assume that the
    # protection space consists of all URIs on the responding server.

    if ($auth_param->{domain}) {
        foreach my $url (split ' ', $auth_param->{domain}) {
            my $relative = URI->new_abs($url, $base_url);
            my $domhost = $relative->host_port();
            my $dompath = $relative->path();
            return 1 if ($host eq $domhost and is_subpath($dompath, $path));
        }
    }
    else {
	my $basehost = $base_url->host_port;
	# we can assume the entire host
	return 1 if $host eq $basehost;
    }

    return 0;
}

 
sub authen_header
{
    my($class, $request, $auth_param, $user, $pass) = @_;

    # increase nonce_count
    if (exists $auth_param->{nonce_count}) {
        $auth_param->{nonce_count}++;
    }
    else {
        $auth_param->{nonce_count} = 0;
    }

    my $nc = sprintf "%08X", $auth_param->{nonce_count};
    my $cnonce = sprintf "%8x", time;

    my $uri = $request->url->path_query;
    $uri = "/" unless length $uri;

    my $md5 = Digest::MD5->new;

    my(@digest);
    $md5->add(join(":", $user, $auth_param->{realm}, $pass));
    push(@digest, $md5->hexdigest);
    $md5->reset;

    push(@digest, $auth_param->{nonce});

    if ($auth_param->{qop}) {
	push(@digest, $nc, $cnonce, ($auth_param->{qop} =~ m|^auth[,;]auth-int$|) ? 'auth' : $auth_param->{qop});
    }

    $md5->add(join(":", $request->method, $uri));
    push(@digest, $md5->hexdigest);
    $md5->reset;

    $md5->add(join(":", @digest));
    my($digest) = $md5->hexdigest;
    $md5->reset;

    my %resp = map { $_ => $auth_param->{$_} } qw(realm nonce opaque);
    @resp{qw(username uri response algorithm)} = ($user, $uri, $digest, "MD5");

    if (($auth_param->{qop} || "") =~ m|^auth([,;]auth-int)?$|) {
	@resp{qw(qop cnonce nc)} = ("auth", $cnonce, $nc);
    }

    my(@order) = qw(username realm qop algorithm uri nonce nc cnonce response);
    if($request->method =~ /^(?:POST|PUT)$/) {
	$md5->add($request->content);
	my $content = $md5->hexdigest;
	$md5->reset;
	$md5->add(join(":", @digest[0..1], $content));
	$md5->reset;
	$resp{"message-digest"} = $md5->hexdigest;
	push(@order, "message-digest");
    }
    push(@order, "opaque");
    my @pairs;
    for (@order) {
	next unless defined $resp{$_};
	push(@pairs, "$_=" . qq("$resp{$_}"));
    }

    my $auth_value  = "Digest " . join(", ", @pairs);

    return $auth_value;
}

1;


 
