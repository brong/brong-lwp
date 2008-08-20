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
	    my($ua, $id, $request, $proxy) = @_;

            return 0 unless ($base_proxy->host eq $proxy->host and
                             $base_proxy->port eq $proxy->port);

	    # check that auth details are still current
            my($newuser, $newpass) = $ua->get_basic_credentials(
	        $auth_param->{realm}, $request->url, $proxy
	    );
            unless (defined $user and defined $pass
	            and $newuser eq $user and $newpass eq $pass) {
		$ua->delete_handler($handler_type, $id);
		return 0;
	    }

	    # ok, we handle this one, add the header
            my $header = $class->authen_header($request, $auth_param,
					       $user, $pass);
	    $request->header('Proxy-Authorization' => $header);

	    # remember this authid was used - for loop detection
	    $request->{authid} = $id;

	    # allow other handlers to chain
	    return 0; 
        };
    }
    else {
	my $base_url = $request->url;
	$handler = sub {
	    my($ua, $id, $request) = @_;

	    return 0 unless $class->handles_request($request, $auth_param,
	    					    $base_url);

	    # check that auth details are still current
            my($newuser, $newpass) = $ua->get_basic_credentials(
	        $auth_param->{realm}, $request->url, $proxy
	    );
            unless (defined $newuser and defined $newpass
	            and $newuser eq $user and $newpass eq $pass) {
		$ua->delete_handler($handler_type, $id);
		return 0;
	    }

	    # ok, we handle this one, add the header
            my $header = $class->authen_header($request, $auth_param,
					       $user, $pass);
	    $request->header('Authorization' => $header);

	    # remember this authid was used - for loop detection
	    $request->{authid} = $id;

	    # allow other handlers to chain
	    return 0; 
	};
    }

    $ua->add_handler($handler_type, $authid, $handler);

    # we don't need to add the header here, because the handler will be
    # called later in the request phase.
    return $ua->request($request, $arg, $size, $response);
}

sub handles_request {
    my ($class, $request, $auth_param, $base_url) = @_;

    my $host = $request->url->host_port;
    my $path = $request->url->path;

    my $basehost = $base_url->host_port;
    my $basepath = $base_url->path;

    # check that the host matches and it's a subpath 
    return 1 if ($basehost eq $host and is_subpath($basepath, $path));

    return 0;
}

# check for subpath strictly by directory, e.g.
#
# is_subpath('/', '/foo') => 1
# is_subpath('/foo', '/foo') => 1
# is_subpath('/foo', '/foobar') => 0
# is_subpath('/foo', '/foo/bar') => 1
# NOTE: is_subpath('/foo/', '/foo') => 0 

sub is_subpath {
    my ($basepath, $path) = @_;

    # shorter - no brainer
    return 0 if length($path) < length($basepath);

    # strip trailing slash if any
    $basepath =~ s{/$}{};

    # match with a slash, easy
    return 1 if ($basepath eq $path);

    # matches with a trailing slash to the same length
    return 1 if substr($path, 0, length($basepath)+1) eq "$basepath/";

    # otherwise it's not a subpath
    return 0;
}

sub authen_header {
    my($class, $request, $auth_param, $user, $pass) = @_;

    my $header = "Basic " . MIME::Base64::encode("$user:$pass", "");

    return $header;
}

1;
