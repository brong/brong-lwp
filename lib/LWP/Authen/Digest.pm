package LWP::Authen::Digest;
use strict;
use base 'LWP::Authen::Basic';

require Digest::MD5;

# use the same logic as Basic to decide when to calculate the header

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
