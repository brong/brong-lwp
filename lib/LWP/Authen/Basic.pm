package LWP::Authen::Basic;
use strict;

require MIME::Base64;

sub authenticate
{
    my($class, $ua, $proxy, $auth_param, $response,
       $request, $arg, $size) = @_;

    my($user, $pass) = $ua->get_basic_credentials($auth_param->{realm},
						  $request->url, $proxy);
    return $response unless defined $user and defined $pass;

    my $host = lc($request->uri->host_port());
    my $authpath = $request->uri->path();

    my $auth_header = $proxy ? "Proxy-Authorization" : "Authorization";

    # Need to check this isn't a repeated fail!
    my $r = $response;
    while ($r) {
	my $auth = $r->request->header($auth_header);
	if ($auth) {
	    # here we know this failed before
	    $response->header("Client-Warning" =>
			      "Credentials for '$user' failed before");
	    delete $ua->{cached_authentication}{$host}{$authpath};
	    return $response;
	}
	$r = $r->previous;
    }

    # store the authenticated path for adding headers
    my $auth_detail
	= $ua->{cached_authentication}{$host}{$authpath} 
	= [$class, $proxy, $auth_param, $user, $pass];

    my $referral = $request->clone;

    $class->add_authen_header($referral, $auth_detail);

    return $ua->request($referral, $arg, $size, $response);
}

sub add_authen_header {
    my($class, $request, $auth_detail) = @_;

    my(undef, $proxy, $auth_param, $user, $pass) = @$auth_detail;

    my $auth_header = $proxy ? "Proxy-Authorization" : "Authorization";
    my $auth_value = "Basic " . MIME::Base64::encode("$user:$pass", "");

    $request->header($auth_header => $auth_value);
}

1;
