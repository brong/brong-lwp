package URI::URL::news;
@ISA = qw(URI::URL::_generic);

sub _parse {
    my($self, $init) = @_;
    $self->{scheme}  = lc($1) if ($init =~ s/^\s*([\w\+\.\-]+)://);
    my $tmp = $self->unescape($init);
    $self->{'grouppart'} = $tmp;
    $self->{ ($tmp =~ m/\@/) ? 'article' : 'group' } = $tmp;
}

sub grouppart { shift->_elem('grouppart', @_) }
sub article   { shift->_elem('article',   @_) }
sub group     { shift->_elem('group',     @_) }
1;