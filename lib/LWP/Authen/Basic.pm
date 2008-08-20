package LWP::Authen::Basic;
use strict;

require MIME::Base64;

sub authenticate
{
    my($class, $ua, $proxy, $auth_param, $response,
       $request, $arg, $size) = @_;

    my $realm = $auth_param->{realm};
    my($user, $pass) = $ua->get_basic_credentials($auth_param->{realm},
						  $request->url, $proxy);
    return $response unless (defined $user and defined $pass);

    my $base_host = lc($request->uri->host_port());

    my ($authid, $handler_type, $handler, $base_proxy);

    if ($proxy) {
	$base_proxy = $ua->_need_proxy($request->url);
	my $proxyhost = $base_proxy->host . ':' . $base_proxy->port;
	$authid = "proxy-$proxyhost-$realm-$user-$pass";
	$handler_type = 'using-proxy';
    }
    else {
	$authid = "auth-$base_host-$realm-$user-$pass";
	$handler_type = 'prepare-request';
    }

    # Need to check this isn't a repeated fail!
    my $r = $response;
    while ($r) {
	my $oldauthid = $r->request->{authid};
	if ($oldauthid and $authid eq $oldauthid) {
	    # here we know this failed before
	    $response->header("Client-Warning" =>
			      "Credentials for '$user' failed before");
	    $ua->delete_handler($handler_type, $authid);
	    return $response;
	}
	$r = $r->previous;
    }

    if ($proxy) { # name isn't ideal.  This is a boolean "is a proxy request"
	$handler = sub {
	    my($ua, $request, $proxy) = @_;

            return 0 unless ($base_proxy->host eq $proxy->host and
                             $base_proxy->port eq $proxy->port);

	    # check that auth details are still current
            my($newuser, $newpass) = $ua->get_basic_credentials(
	        $auth_param->{realm}, $request->url, $proxy
	    );
            unless (defined $user and defined $pass
	            and $newuser eq $user and $newpass eq $pass) {
		$ua->delete_handler($handler_type, $authid);
		return 0;
	    }

            my $header = $class->authen_header($auth_param, $user, $pass);
	    $request->header('Proxy-Authorization' => $header);
	    $request->{authid} = $authid;

	    return 0; # allow other handlers to chain
        };
    }
    else {
	my $base_path = $request->url->path;
	$base_path =~ s{/$}{}; # remove
	$handler = sub {
	    my($ua, $request, $proxy) = @_;

	    my $host = $request->url->host_port;
	    my $path = $request->url->path;

	    # check that the host matches
	    return 0 unless $base_host eq $host;

	    # check that it's a subpath
            return 0 if length($path) < length($base_path); # no brainer.
	    return 0 unless (
		$path eq $base_path or
		substr($path, 0, length($base_path)+1) eq "$base_path/"
            );

	    # check that auth details are still current
            my($newuser, $newpass) = $ua->get_basic_credentials(
	        $auth_param->{realm}, $request->url, $proxy
	    );
            unless (defined $user and defined $pass
	            and $newuser eq $user and $newpass eq $pass) {
		$ua->delete_handler($handler_type, $authid);
		return 0;
	    }

	    # ok, we handle this one, add the header

            my $header = $class->authen_header($auth_param, $user, $pass);
	    $request->header('Authorization' => $header);
	    $request->{authid} = $authid;

	    return 0; # allow other handlers to chain
	};
    }

    $ua->add_handler($handler_type, $authid, $handler);

    # we don't need to add the header here, because the handler will be
    # called later in the request phase.
    return $ua->request($request, $arg, $size, $response);
}

sub authen_header {
    my($class, $auth_param, $user, $pass) = @_;

    my $header = "Basic " . MIME::Base64::encode("$user:$pass", "");

    return $header;
}

1;
