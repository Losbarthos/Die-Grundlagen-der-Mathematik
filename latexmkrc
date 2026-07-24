# Standalone band dependency builds for xr-hyper and thmlookup.
#
# The official latexmk xr example uses a tex -> aux custom dependency whose
# source and destination share a basename.  This project intentionally maps,
# for example, B03.tex to registry/_B03.aux, so that stock rule cannot express
# the dependency.  The documented before_xlatex hook below implements the
# equivalent preflight explicitly: before a standalone target is evaluated,
# all of its transitive predecessors are updated in topological order.

use Cwd qw(abs_path getcwd);
use Digest::SHA ();
use File::Basename qw(basename dirname);
use File::Copy qw(copy);
use File::Find qw(find);
use File::Spec;

# Overleaf reads a root-level latexmkrc automatically.  Select LuaLaTeX even
# when the UI has not been configured separately for this project.
$pdf_mode = 4;

# Give standalone band downloads descriptive names while keeping the short,
# stable TeX basenames used by the dependency and cross-reference machinery.
my %dgm_download_jobnames = (
    B01 => 'B01 - Grundlagen der Logik',
    B02 => 'B02 - Theoreme der Logik',
    B03 => 'B03 - Mengenlehre',
    B04 => 'B04 - Funktionen',
    B05 => 'B05 - Äquivalenzrelationen',
    B06 => 'B06 - Ordnungsrelationen',
    B07 => 'B07 - Die natürlichen Zahlen',
    B08 => 'B08 - Endliche Mengen',
    B09 => 'B09 - Verbände',
    B10 => 'B10 - Frankls Vermutung',
);
for my $argument (@ARGV) {
    my $leaf = basename($argument);
    if ($leaf =~ /\A(B(?:0[1-9]|10))\.tex\z/i) {
        my $band = uc($1);
        $jobname = $dgm_download_jobnames{$band};
    }
}

# A before_xlatex hook only runs when latexmk schedules an engine pass.  Require
# one outer pass per invocation so a changed predecessor cannot be hidden behind
# an older, still-present imported AUX.  Nested dependency builds carry the
# guard below; complete ones use -gt to force exactly one *latex pass, because
# Lua-read registry TSV files are not visible in LaTeX's FLS dependency data.
$go_mode = 3
    if ($ENV{DGM_LATEXMK_INTERNAL_SUBBUILD} || '') ne '1';

my $dgm_rc_dir = dirname(__FILE__);
$dgm_rc_dir = '.' if !defined($dgm_rc_dir) || $dgm_rc_dir eq '';
my $dgm_repo_root = abs_path($dgm_rc_dir);
die "latexmkrc: cannot resolve repository root from " . __FILE__ . "\n"
    if !defined $dgm_repo_root;

my $dgm_graph_path = File::Spec->catfile(
    $dgm_repo_root,
    'band-dependencies.tsv'
);
my $dgm_cache_inputs_path = File::Spec->catfile(
    $dgm_repo_root,
    'cache-inputs.tsv'
);

sub dgm_root_path {
    my ($relative) = @_;
    my @parts = split m{/}, $relative;
    return File::Spec->catfile($dgm_repo_root, @parts);
}

sub dgm_trim {
    my ($value) = @_;
    $value = '' if !defined $value;
    $value =~ s/^\s+//;
    $value =~ s/\s+$//;
    return $value;
}

sub dgm_read_graph {
    my ($path) = @_;
    open my $handle, '<:encoding(UTF-8)', $path
        or die "latexmkrc: cannot read $path: $!\n";

    my $header = <$handle>;
    die "latexmkrc: empty dependency graph $path\n" if !defined $header;
    $header =~ s/^\x{FEFF}//;
    $header =~ s/\r?\n$//;
    my $expected_header = join "\t", qw(
        band source artifact_base predecessors
    );
    die "latexmkrc: invalid header in $path\n"
        if $header ne $expected_header;

    my %graph;
    my %source_owner;
    my %artifact_owner;
    my @order;
    my $line_number = 1;

    while (my $line = <$handle>) {
        ++$line_number;
        $line =~ s/\r?\n$//;
        next if $line =~ /^\s*(?:#.*)?$/;

        my @columns = split /\t/, $line, -1;
        die "latexmkrc: $path:$line_number: expected four TSV columns\n"
            if @columns != 4;

        my ($band, $source, $artifact_base, $predecessor_text) =
            map { dgm_trim($_) } @columns;

        die "latexmkrc: $path:$line_number: invalid band '$band'\n"
            if $band !~ /^B\d{2}$/;
        die "latexmkrc: $path:$line_number: duplicate band '$band'\n"
            if exists $graph{$band};

        die "latexmkrc: $path:$line_number: invalid source '$source'\n"
            if $source !~ m{^[A-Za-z0-9][A-Za-z0-9_.\-/]*\.tex$}
                || $source =~ m{(?:^|/)\.\.(?:/|$)}
                || File::Spec->file_name_is_absolute($source);
        die "latexmkrc: $path:$line_number: source does not exist: $source\n"
            if !-f dgm_root_path($source);
        die "latexmkrc: $path:$line_number: source '$source' is used by both "
            . "$source_owner{$source} and $band\n"
            if exists $source_owner{$source};

        # Keep the build products below registry/ and require a fixed _Bxx-like
        # basename.  The value is an explicit source-to-artifact mapping, not a
        # basename-preserving tex -> aux convention.
        my $expected_artifact_base = "registry/_$band";
        die "latexmkrc: $path:$line_number: artifact base for $band must "
            . "be '$expected_artifact_base', got '$artifact_base'\n"
            if $artifact_base ne $expected_artifact_base;
        die "latexmkrc: $path:$line_number: artifact base '$artifact_base' "
            . "is used by both $artifact_owner{$artifact_base} and $band\n"
            if exists $artifact_owner{$artifact_base};

        my @predecessors;
        my %listed;
        if ($predecessor_text ne '' && $predecessor_text ne '-') {
            for my $predecessor (split /,/, $predecessor_text, -1) {
                $predecessor = dgm_trim($predecessor);
                die "latexmkrc: $path:$line_number: invalid predecessor "
                    . "'$predecessor' for $band\n"
                    if $predecessor !~ /^B\d{2}$/;
                die "latexmkrc: $path:$line_number: duplicate predecessor "
                    . "'$predecessor' for $band\n"
                    if $listed{$predecessor}++;
                push @predecessors, $predecessor;
            }
        }

        $graph{$band} = {
            band          => $band,
            source        => $source,
            artifact_base => $artifact_base,
            predecessors  => \@predecessors,
        };
        $source_owner{$source} = $band;
        $artifact_owner{$artifact_base} = $band;
        push @order, $band;
    }
    close $handle
        or die "latexmkrc: cannot close $path: $!\n";

    die "latexmkrc: dependency graph $path contains no bands\n" if !@order;

    my %position;
    for my $index (0 .. $#order) {
        $position{$order[$index]} = $index;
    }
    for my $band (@order) {
        for my $predecessor (@{$graph{$band}->{predecessors}}) {
            die "latexmkrc: unknown predecessor '$predecessor' of $band\n"
                if !exists $graph{$predecessor};
            die "latexmkrc: graph is not topologically ordered: "
                . "$predecessor must precede $band\n"
                if $position{$predecessor} >= $position{$band};
        }
    }

    # A separate DFS gives a direct cycle check and also protects future graph
    # edits if the file-order validation above is ever relaxed.
    my %state;
    my $visit;
    $visit = sub {
        my ($band, $trail) = @_;
        if (($state{$band} || 0) == 1) {
            die "latexmkrc: dependency cycle: $trail -> $band\n";
        }
        return if ($state{$band} || 0) == 2;
        $state{$band} = 1;
        for my $predecessor (@{$graph{$band}->{predecessors}}) {
            $visit->($predecessor, "$trail -> $predecessor");
        }
        $state{$band} = 2;
    };
    for my $band (@order) {
        $visit->($band, $band);
    }

    return (\%graph, \@order);
}

my ($dgm_graph, $dgm_graph_order) = dgm_read_graph($dgm_graph_path);

my %dgm_band_by_source_leaf;
for my $band (@{$dgm_graph_order}) {
    my $leaf = basename($dgm_graph->{$band}->{source});
    die "latexmkrc: source basename '$leaf' is ambiguous\n"
        if exists $dgm_band_by_source_leaf{$leaf};
    $dgm_band_by_source_leaf{$leaf} = $band;
}

sub dgm_transitive_predecessors {
    my ($target) = @_;
    my %seen;
    my @result;
    my $visit;
    $visit = sub {
        my ($band) = @_;
        for my $predecessor (@{$dgm_graph->{$band}->{predecessors}}) {
            next if $seen{$predecessor}++;
            $visit->($predecessor);
            push @result, $predecessor;
        }
    };
    $visit->($target);

    # DFS above is topological, but sorting by the validated canonical file
    # order also makes the chosen order obvious and stable for redundant edges.
    my %position;
    for my $index (0 .. $#{$dgm_graph_order}) {
        $position{$dgm_graph_order->[$index]} = $index;
    }
    @result = sort { $position{$a} <=> $position{$b} } @result;
    return @result;
}

sub dgm_cache_safe_relative {
    my ($relative) = @_;
    return 0 if !defined $relative || $relative eq '';
    return 0 if File::Spec->file_name_is_absolute($relative);
    return 0 if $relative !~ m{\A[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\z};
    for my $segment (split m{/}, $relative, -1) {
        return 0 if $segment eq '.' || $segment eq '..';
    }
    return 1;
}

sub dgm_cache_assert_child_path {
    my ($root, $relative, $description) = @_;
    die "latexmkrc: cache: unsafe $description path '$relative'\n"
        if !dgm_cache_safe_relative($relative);
    die "latexmkrc: cache: $description root is a symlink: $root\n"
        if -l $root;
    die "latexmkrc: cache: $description root is not a directory: $root\n"
        if !-d $root;

    my $current = $root;
    for my $segment (split m{/}, $relative) {
        $current = File::Spec->catfile($current, $segment);
        die "latexmkrc: cache: symlink is forbidden in $description: "
            . "$current\n"
            if -l $current;
    }
    return $current;
}

sub dgm_cache_relative_path {
    my ($root, $path, $description) = @_;
    my $relative = File::Spec->abs2rel($path, $root);
    $relative =~ s{\\}{/}g;
    die "latexmkrc: cache: $description escapes $root: $path\n"
        if !dgm_cache_safe_relative($relative);
    return $relative;
}

sub dgm_cache_assert_exact_set {
    my ($description, $expected, $actual) = @_;
    my @missing = sort grep { !exists $actual->{$_} } keys %{$expected};
    my @extra = sort grep { !exists $expected->{$_} } keys %{$actual};
    return if !@missing && !@extra;

    die "latexmkrc: cache: $description mismatch; missing: "
        . (@missing ? join(', ', @missing) : '(none)')
        . '; extra: '
        . (@extra ? join(', ', @extra) : '(none)')
        . "\n";
}

sub dgm_cache_forbidden_input_path {
    my ($path) = @_;
    return $path =~ m{
        \A(?:\.git|registry|registry-cache|\.registry-cache-[^/]+)
        (?:/|\z)
    }x;
}

sub dgm_cache_read_input_specs {
    open my $handle, '<:encoding(UTF-8)', $dgm_cache_inputs_path
        or die "latexmkrc: cache: cannot read $dgm_cache_inputs_path: $!\n";
    my @lines = <$handle>;
    close $handle
        or die "latexmkrc: cache: cannot close $dgm_cache_inputs_path: $!\n";
    for my $line (@lines) {
        $line =~ s/\r?\n\z//;
    }
    $lines[0] =~ s/^\x{FEFF}// if @lines;
    die "latexmkrc: cache: input specification is truncated\n"
        if @lines < 2;
    die "latexmkrc: cache: invalid input specification header\n"
        if $lines[0] ne "kind\tpath";

    my (@specs, %seen);
    for my $index (1 .. $#lines) {
        next if $lines[$index] =~ /^\s*(?:#.*)?\z/;
        my @columns = split /\t/, $lines[$index], -1;
        my $line_number = $index + 1;
        die "latexmkrc: cache: input specification line $line_number "
            . "must have two TSV fields\n"
            if @columns != 2;
        my ($kind, $path) = map { dgm_trim($_) } @columns;
        die "latexmkrc: cache: unknown input kind '$kind' at line "
            . "$line_number\n"
            if $kind ne 'file' && $kind ne 'tree'
                && $kind ne 'root_extension';
        if ($kind eq 'root_extension') {
            die "latexmkrc: cache: invalid root extension '$path'\n"
                if $path !~ /\A\.[A-Za-z0-9]+\z/;
        }
        else {
            die "latexmkrc: cache: unsafe configured input '$path'\n"
                if !dgm_cache_safe_relative($path)
                    || dgm_cache_forbidden_input_path($path);
        }
        my $key = "$kind\t$path";
        die "latexmkrc: cache: duplicate input specification '$key'\n"
            if $seen{$key}++;
        push @specs, { kind => $kind, path => $path };
    }
    die "latexmkrc: cache: input specification has no rows\n" if !@specs;
    return \@specs;
}

sub dgm_cache_expected_sources {
    my ($specs) = @_;
    my %sources;
    for my $spec (@{$specs}) {
        my ($kind, $path) = @{$spec}{qw(kind path)};
        if ($kind eq 'file') {
            my $full_path = dgm_cache_assert_child_path(
                $dgm_repo_root,
                $path,
                'configured input file'
            );
            die "latexmkrc: cache: configured input file is missing: "
                . "$path\n"
                if !-f $full_path;
            $sources{$path} = 1;
        }
        elsif ($kind eq 'tree') {
            my $tree_root = dgm_cache_assert_child_path(
                $dgm_repo_root,
                $path,
                'configured input tree'
            );
            die "latexmkrc: cache: configured input tree is missing: "
                . "$path\n"
                if !-d $tree_root;
            find(
                {
                    no_chdir => 1,
                    wanted   => sub {
                        my $member = $File::Find::name;
                        die "latexmkrc: cache: symlink below input tree "
                            . "is forbidden: $member\n"
                            if -l $member;
                        return if -d $member;
                        die "latexmkrc: cache: non-file below input tree "
                            . "is forbidden: $member\n"
                            if !-f $member;
                        my $relative = dgm_cache_relative_path(
                            $dgm_repo_root,
                            $member,
                            'configured input tree member'
                        );
                        die "latexmkrc: cache: generated path occurred in "
                            . "input tree: $relative\n"
                            if dgm_cache_forbidden_input_path($relative);
                        $sources{$relative} = 1;
                    },
                },
                $tree_root
            );
        }
        else {
            opendir my $root_handle, $dgm_repo_root
                or die "latexmkrc: cache: cannot enumerate repository "
                    . "root: $!\n";
            my @entries = sort readdir $root_handle;
            closedir $root_handle
                or die "latexmkrc: cache: cannot close repository root: "
                    . "$!\n";
            for my $entry (@entries) {
                next if $entry eq '.' || $entry eq '..';
                next if $entry !~ /\Q$path\E\z/;
                die "latexmkrc: cache: unsafe root input '$entry'\n"
                    if !dgm_cache_safe_relative($entry);
                my $full_path = File::Spec->catfile($dgm_repo_root, $entry);
                die "latexmkrc: cache: root input is a symlink: $entry\n"
                    if -l $full_path;
                die "latexmkrc: cache: root input is not a file: $entry\n"
                    if !-f $full_path;
                $sources{$entry} = 1;
            }
        }
    }

    die "latexmkrc: cache: cache-inputs.tsv must include itself\n"
        if !exists $sources{'cache-inputs.tsv'};
    for my $band (@{$dgm_graph_order}) {
        my $source = $dgm_graph->{$band}->{source};
        die "latexmkrc: cache: dependency source is not covered by "
            . "cache-inputs.tsv: $source\n"
            if !exists $sources{$source};
    }
    return \%sources;
}

sub dgm_cache_expected_sets {
    my ($predecessors) = @_;
    my $canonical = join ',', @{$predecessors};
    die "latexmkrc: cache: B05 requires predecessors B01,B02,B03,B04; "
        . "got '$canonical'\n"
        if $canonical ne 'B01,B02,B03,B04';

    my $input_specs = dgm_cache_read_input_specs();
    my $sources = dgm_cache_expected_sources($input_specs);

    my (%artifacts, %metadata);
    for my $band (@{$predecessors}) {
        my $base = $dgm_graph->{$band}->{artifact_base};
        for my $suffix (qw(aux pdf registry.tsv debug.log)) {
            my $live = "$base.$suffix";
            $artifacts{$live} = "files/$live";
        }
        my $log = "$base.log";
        $metadata{$log} = "metadata/$log";
    }
    my %tools = map { $_ => 1 } qw(
        PowerShell
        latexmk
        lualatex
        pdftotext
    );

    my %tree_files = ( 'manifest.tsv' => 1 );
    $tree_files{$_} = 1 for values %artifacts;
    $tree_files{$_} = 1 for values %metadata;
    my %tree_directories = map { $_ => 1 } qw(
        files
        files/registry
        metadata
        metadata/registry
    );

    return {
        source           => $sources,
        artifact         => \%artifacts,
        metadata         => \%metadata,
        tool             => \%tools,
        tree_files       => \%tree_files,
        tree_directories => \%tree_directories,
    };
}

sub dgm_cache_read_manifest {
    my ($cache_root) = @_;
    my $manifest = dgm_cache_assert_child_path(
        $cache_root,
        'manifest.tsv',
        'manifest'
    );
    die "latexmkrc: cache: manifest is not a regular file: $manifest\n"
        if !-f $manifest;

    open my $handle, '<:encoding(UTF-8)', $manifest
        or die "latexmkrc: cache: cannot read $manifest: $!\n";
    my @lines = <$handle>;
    close $handle
        or die "latexmkrc: cache: cannot close $manifest: $!\n";
    for my $line (@lines) {
        $line =~ s/\r?\n\z//;
    }
    $lines[0] =~ s/^\x{FEFF}// if @lines;

    die "latexmkrc: cache: manifest is truncated: $manifest\n"
        if @lines < 3;
    die "latexmkrc: cache: unsupported manifest version\n"
        if $lines[0] ne "manifest_version\t1";
    die "latexmkrc: cache: invalid manifest header\n"
        if $lines[1] ne join "\t", qw(
            kind path cache_path size sha256 value
        );

    my %rows = map { $_ => {} } qw(source artifact metadata tool);
    for my $index (2 .. $#lines) {
        my $line_number = $index + 1;
        die "latexmkrc: cache: empty manifest row at line $line_number\n"
            if $lines[$index] eq '';
        my @columns = split /\t/, $lines[$index], -1;
        die "latexmkrc: cache: manifest line $line_number must have "
            . "six TSV fields\n"
            if @columns != 6;
        my ($kind, $path, $cache_path, $size, $sha256, $value) =
            @columns;
        die "latexmkrc: cache: unknown kind '$kind' at line "
            . "$line_number\n"
            if !exists $rows{$kind};
        die "latexmkrc: cache: unsafe path '$path' at line "
            . "$line_number\n"
            if !dgm_cache_safe_relative($path);
        die "latexmkrc: cache: duplicate $kind row '$path'\n"
            if exists $rows{$kind}->{$path};

        if ($kind eq 'tool') {
            die "latexmkrc: cache: malformed tool row '$path'\n"
                if $cache_path ne '' || $size ne '' || $sha256 ne ''
                    || $value eq '';
        }
        else {
            die "latexmkrc: cache: malformed file row '$path'\n"
                if $size !~ /\A(?:0|[1-9][0-9]*)\z/
                    || $sha256 !~ /\A[0-9a-f]{64}\z/
                    || $value ne '';
            if ($kind eq 'source') {
                die "latexmkrc: cache: source row has cache path: "
                    . "$path\n"
                    if $cache_path ne '';
                die "latexmkrc: cache: source input is empty: $path\n"
                    if $size eq '0';
            }
            else {
                die "latexmkrc: cache: unsafe cache path '$cache_path'\n"
                    if !dgm_cache_safe_relative($cache_path);
                my $empty_allowed =
                    $kind eq 'artifact' && $path =~ /\.debug\.log\z/;
                die "latexmkrc: cache: unexpectedly empty $kind: $path\n"
                    if $size eq '0' && !$empty_allowed;
            }
        }

        $rows{$kind}->{$path} = {
            kind       => $kind,
            path       => $path,
            cache_path => $cache_path,
            size       => $size,
            sha256     => $sha256,
            value      => $value,
        };
    }
    return \%rows;
}

sub dgm_cache_sha256_file {
    my ($path, $description) = @_;
    open my $handle, '<:raw', $path
        or die "latexmkrc: cache: cannot read $description $path: $!\n";
    my $digest = Digest::SHA->new(256);
    $digest->addfile($handle);
    close $handle
        or die "latexmkrc: cache: cannot close $description $path: $!\n";
    return $digest->hexdigest;
}

sub dgm_cache_assert_file_matches {
    my ($path, $row, $description, $empty_allowed) = @_;
    die "latexmkrc: cache: $description is a symlink: $path\n"
        if -l $path;
    die "latexmkrc: cache: $description is missing: $path\n"
        if !-f $path;
    my $size = -s $path;
    die "latexmkrc: cache: cannot determine size of $description: $path\n"
        if !defined $size;
    die "latexmkrc: cache: empty $description: $path\n"
        if !$empty_allowed && $size == 0;
    die "latexmkrc: cache: size mismatch for $description $path; "
        . "manifest=$row->{size}, actual=$size\n"
        if "$size" ne $row->{size};
    my $sha256 = dgm_cache_sha256_file($path, $description);
    die "latexmkrc: cache: SHA-256 mismatch for $description $path; "
        . "manifest=$row->{sha256}, actual=$sha256\n"
        if $sha256 ne $row->{sha256};
}

sub dgm_cache_assert_exact_tree {
    my ($cache_root, $expected) = @_;
    die "latexmkrc: cache: cache root is a symlink: $cache_root\n"
        if -l $cache_root;
    die "latexmkrc: cache: cache root is not a directory: $cache_root\n"
        if !-d $cache_root;

    my (%files, %directories);
    find(
        {
            no_chdir => 1,
            wanted   => sub {
                my $path = $File::Find::name;
                return if File::Spec->canonpath($path) eq
                    File::Spec->canonpath($cache_root);
                die "latexmkrc: cache: symlink in cache tree: $path\n"
                    if -l $path;
                my $relative = dgm_cache_relative_path(
                    $cache_root,
                    $path,
                    'cache member'
                );
                if (-f $path) {
                    die "latexmkrc: cache: duplicate file in cache tree: "
                        . "$relative\n"
                        if $files{$relative}++;
                }
                elsif (-d $path) {
                    die "latexmkrc: cache: duplicate directory in cache "
                        . "tree: $relative\n"
                        if $directories{$relative}++;
                }
                else {
                    die "latexmkrc: cache: non-file in cache tree: $path\n";
                }
            },
        },
        $cache_root
    );
    dgm_cache_assert_exact_set(
        'cache files',
        $expected->{tree_files},
        \%files
    );
    dgm_cache_assert_exact_set(
        'cache directories',
        $expected->{tree_directories},
        \%directories
    );
}

sub dgm_cache_validate {
    my ($predecessors) = @_;
    my $cache_root = dgm_root_path('registry-cache');
    die "latexmkrc: cache: cache root is a symlink: $cache_root\n"
        if -l $cache_root;
    die "latexmkrc: cache: cache root is missing: $cache_root\n"
        if !-d $cache_root;

    my $expected = dgm_cache_expected_sets($predecessors);
    my $rows = dgm_cache_read_manifest($cache_root);
    for my $kind (qw(source artifact metadata tool)) {
        my %actual = map { $_ => 1 } keys %{$rows->{$kind}};
        dgm_cache_assert_exact_set(
            "manifest $kind rows",
            $expected->{$kind},
            \%actual
        );
    }

    for my $path (sort keys %{$rows->{artifact}}) {
        my $expected_cache_path = $expected->{artifact}->{$path};
        die "latexmkrc: cache: artifact '$path' has cache path "
            . "'$rows->{artifact}->{$path}->{cache_path}', expected "
            . "'$expected_cache_path'\n"
            if $rows->{artifact}->{$path}->{cache_path} ne
                $expected_cache_path;
    }
    for my $path (sort keys %{$rows->{metadata}}) {
        my $expected_cache_path = $expected->{metadata}->{$path};
        die "latexmkrc: cache: metadata '$path' has cache path "
            . "'$rows->{metadata}->{$path}->{cache_path}', expected "
            . "'$expected_cache_path'\n"
            if $rows->{metadata}->{$path}->{cache_path} ne
                $expected_cache_path;
    }

    dgm_cache_assert_exact_tree($cache_root, $expected);

    for my $path (sort keys %{$rows->{source}}) {
        my $full_path = dgm_cache_assert_child_path(
            $dgm_repo_root,
            $path,
            'source input'
        );
        dgm_cache_assert_file_matches(
            $full_path,
            $rows->{source}->{$path},
            "source input '$path'",
            0
        );
    }
    for my $kind (qw(artifact metadata)) {
        for my $path (sort keys %{$rows->{$kind}}) {
            my $row = $rows->{$kind}->{$path};
            my $full_path = dgm_cache_assert_child_path(
                $cache_root,
                $row->{cache_path},
                "cached $kind"
            );
            my $empty_allowed =
                $kind eq 'artifact' && $path =~ /\.debug\.log\z/;
            dgm_cache_assert_file_matches(
                $full_path,
                $row,
                "cached $kind '$path'",
                $empty_allowed
            );
        }
    }

    return ($cache_root, $rows);
}

sub dgm_cache_restore_b05 {
    my ($predecessors) = @_;
    my ($cache_root, $rows) = dgm_cache_validate($predecessors);
    my $registry_dir = dgm_root_path('registry');
    die "latexmkrc: cache: registry path is a symlink: $registry_dir\n"
        if -l $registry_dir;
    if (!-e $registry_dir) {
        mkdir $registry_dir
            or die "latexmkrc: cache: cannot create $registry_dir: $!\n";
    }
    die "latexmkrc: cache: registry path is not a directory: "
        . "$registry_dir\n"
        if !-d $registry_dir;

    my $token = join '-', time, $$, int(rand(1_000_000_000));
    my @staged;
    my $stage_ok = eval {
        my $index = 0;
        for my $live_path (sort keys %{$rows->{artifact}}) {
            ++$index;
            my $row = $rows->{artifact}->{$live_path};
            my $source = dgm_cache_assert_child_path(
                $cache_root,
                $row->{cache_path},
                'cached artifact'
            );
            my $destination = dgm_cache_assert_child_path(
                $dgm_repo_root,
                $live_path,
                'live registry artifact'
            );
            die "latexmkrc: cache: live registry artifact is not a "
                . "regular file: $destination\n"
                if (-e $destination || -l $destination)
                    && !-f $destination;

            my $temporary = File::Spec->catfile(
                $registry_dir,
                ".dgm-cache-$token-$index.tmp"
            );
            my $backup = File::Spec->catfile(
                $registry_dir,
                ".dgm-cache-$token-$index.backup"
            );
            die "latexmkrc: cache: staging collision: $temporary\n"
                if -e $temporary || -l $temporary
                    || -e $backup || -l $backup;
            my $entry = {
                row         => $row,
                live_path   => $live_path,
                destination => $destination,
                temporary   => $temporary,
                backup      => $backup,
                backed_up   => 0,
                installed   => 0,
            };
            push @staged, $entry;
            copy($source, $temporary)
                or die "latexmkrc: cache: cannot stage $source as "
                    . "$temporary: $!\n";
            my $empty_allowed = $live_path =~ /\.debug\.log\z/;
            dgm_cache_assert_file_matches(
                $temporary,
                $row,
                "staged artifact '$live_path'",
                $empty_allowed
            );
        }
        1;
    };
    if (!$stage_ok) {
        my $error = $@ || 'unknown staging failure';
        my @cleanup_errors;
        for my $entry (@staged) {
            next if !-e $entry->{temporary} && !-l $entry->{temporary};
            push @cleanup_errors, $entry->{temporary}
                if !unlink $entry->{temporary};
        }
        die "latexmkrc: cache: restore staging failed: $error"
            . (@cleanup_errors
                ? 'cleanup also failed for: '
                    . join(', ', @cleanup_errors) . "\n"
                : '');
    }

    my $commit_ok = eval {
        for my $entry (@staged) {
            my $destination = $entry->{destination};
            die "latexmkrc: cache: destination became a symlink: "
                . "$destination\n"
                if -l $destination;
            if (-e $destination) {
                die "latexmkrc: cache: destination became non-regular: "
                    . "$destination\n"
                    if !-f $destination;
                rename $destination, $entry->{backup}
                    or die "latexmkrc: cache: cannot back up $destination: "
                        . "$!\n";
                $entry->{backed_up} = 1;
            }
            rename $entry->{temporary}, $destination
                or die "latexmkrc: cache: cannot install $destination: $!\n";
            $entry->{installed} = 1;
        }

        # Verification happens before backups are removed, so a late disk or
        # antivirus error can still be rolled back to the complete old set.
        for my $entry (@staged) {
            my $empty_allowed = $entry->{live_path} =~ /\.debug\.log\z/;
            dgm_cache_assert_file_matches(
                $entry->{destination},
                $entry->{row},
                "installed artifact '$entry->{live_path}'",
                $empty_allowed
            );
        }
        1;
    };
    if (!$commit_ok) {
        my $error = $@ || 'unknown commit failure';
        my @rollback_errors;
        for my $entry (reverse @staged) {
            if ($entry->{installed}
                && (-e $entry->{destination} || -l $entry->{destination})) {
                push @rollback_errors, "remove $entry->{destination}"
                    if !unlink $entry->{destination};
            }
            if ($entry->{backed_up}) {
                push @rollback_errors,
                    "restore $entry->{backup} -> $entry->{destination}"
                    if !rename $entry->{backup}, $entry->{destination};
            }
            if (-e $entry->{temporary} || -l $entry->{temporary}) {
                push @rollback_errors, "remove $entry->{temporary}"
                    if !unlink $entry->{temporary};
            }
        }
        die "latexmkrc: cache: restore commit failed and was rolled back: "
            . "$error"
            . (@rollback_errors
                ? 'rollback errors: ' . join(', ', @rollback_errors) . "\n"
                : '');
    }

    my @cleanup_errors;
    for my $entry (@staged) {
        next if !$entry->{backed_up};
        push @cleanup_errors, $entry->{backup}
            if !unlink $entry->{backup};
    }
    die "latexmkrc: cache: installed all artifacts, but could not remove "
        . 'backup files: ' . join(', ', @cleanup_errors) . "\n"
        if @cleanup_errors;

    for my $band (@{$predecessors}) {
        dgm_verify_artifacts($band);
    }
    my @tool_versions = map {
        "$_=$rows->{tool}->{$_}->{value}"
    } sort keys %{$rows->{tool}};
    print "latexmkrc: restored verified B05 predecessor cache; recorded "
        . 'tools: ' . join('; ', @tool_versions) . "\n";
    return 1;
}

sub dgm_artifacts_complete {
    my ($spec) = @_;
    for my $suffix (qw(.aux .pdf .registry.tsv .debug.log .fdb_latexmk)) {
        my $path = dgm_root_path($spec->{artifact_base} . $suffix);
        return 0 if !-f $path;
        return 0 if $suffix ne '.debug.log' && !-s $path;
    }
    return 1;
}

sub dgm_verify_artifacts {
    my ($band) = @_;
    my $spec = $dgm_graph->{$band};
    for my $suffix (qw(.aux .pdf .registry.tsv .debug.log)) {
        my $relative = $spec->{artifact_base} . $suffix;
        my $path = dgm_root_path($relative);
        die "latexmkrc: $band build did not produce $relative\n" if !-f $path;
        next if $suffix eq '.debug.log';
        die "latexmkrc: $band build produced empty $relative\n" if !-s $path;
    }
}

sub dgm_build_predecessor {
    my ($band) = @_;
    my $spec = $dgm_graph->{$band};
    my $artifact_dir = dirname($spec->{artifact_base});
    my $jobname = basename($spec->{artifact_base});

    my @arguments;
    if (($ENV{DGM_LATEXMK_FORCE_DEPS} || '') eq '1'
        || !dgm_artifacts_complete($spec)) {
        push @arguments, '-gg';
    }
    else {
        # Even if latexmk considers the PDF/AUX current, refresh the Lua
        # registry consumer once.  A predecessor registry can change while its
        # AUX remains byte-identical, and raw Lua io.open calls are absent from
        # the .fls/.fdb_latexmk dependency graph.
        push @arguments, '-gt';
    }
    push @arguments,
        '-lualatex',
        '-interaction=nonstopmode',
        '-halt-on-error',
        '-file-line-error',
        "-outdir=$artifact_dir",
        "-jobname=$jobname",
        $spec->{source};

    print "latexmkrc: updating $band ($spec->{source} -> "
        . "$spec->{artifact_base}.{aux,pdf,registry.tsv,debug.log})\n";

    my $old_directory = getcwd();
    die "latexmkrc: cannot determine current directory\n"
        if !defined $old_directory;
    chdir $dgm_repo_root
        or die "latexmkrc: cannot enter $dgm_repo_root: $!\n";
    my $status = system 'latexmk', @arguments;
    my $restore_ok = chdir $old_directory;
    die "latexmkrc: cannot restore directory $old_directory: $!\n"
        if !$restore_ok;

    if ($status == -1) {
        die "latexmkrc: failed to start latexmk for $band: $!\n";
    }
    if ($status != 0) {
        my $exit_code = $status >> 8;
        die "latexmkrc: latexmk failed for $band (exit $exit_code)\n";
    }

    dgm_verify_artifacts($band);
}

my %dgm_prepared_targets;
sub dgm_prepare_band_dependencies {
    # Nested latexmk processes read this rc file too.  The outer process has
    # already chosen their topological position, so they must not recurse.
    return 0 if ($ENV{DGM_LATEXMK_INTERNAL_SUBBUILD} || '') eq '1';

    my $source = (defined $Psource && defined $$Psource) ? $$Psource : '';
    $source =~ s{\\}{/}g;
    my $source_leaf = basename($source);
    my $target = $dgm_band_by_source_leaf{$source_leaf};
    return 0 if !defined $target;
    return 0 if $dgm_prepared_targets{$target};

    my @predecessors = dgm_transitive_predecessors($target);
    my $cache_restored = 0;
    if ($target eq 'B05') {
        my $cache_root = dgm_root_path('registry-cache');
        my $cache_exists = -e $cache_root || -l $cache_root;
        if (($ENV{DGM_LATEXMK_FORCE_DEPS} || '') eq '1') {
            print "latexmkrc: DGM_LATEXMK_FORCE_DEPS=1; bypassing the B05 "
                . "cache and rebuilding all predecessors\n"
                if $cache_exists;
        }
        elsif ($cache_exists) {
            die "latexmkrc: cache: registry-cache is a symlink: "
                . "$cache_root\n"
                if -l $cache_root;
            die "latexmkrc: cache: registry-cache is not a directory: "
                . "$cache_root\n"
                if !-d $cache_root;
            my $cache_manifest = File::Spec->catfile(
                $cache_root,
                'manifest.tsv'
            );
            die "latexmkrc: cache: registry-cache exists without "
                . "manifest.tsv; refusing a silent partial cache\n"
                if !-e $cache_manifest && !-l $cache_manifest;
            print "latexmkrc: B05 cache manifest found; validating the "
                . "complete cache before touching registry/\n";
            $cache_restored = dgm_cache_restore_b05(\@predecessors);
        }
    }
    if (@predecessors) {
        if ($cache_restored) {
            print "latexmkrc: skipping B01--B04 precursor builds because "
                . "the verified cache was restored as a staged, "
                . "rollback-protected set\n";
        }
        else {
            print "latexmkrc: preparing $target predecessors: "
                . join(', ', @predecessors) . "\n";
            local $ENV{DGM_LATEXMK_INTERNAL_SUBBUILD} = '1';
            for my $predecessor (@predecessors) {
                dgm_build_predecessor($predecessor);
            }
        }
    }

    $dgm_prepared_targets{$target} = 1;
    return 0;
}

my $dgm_hook_registered = add_hook(
    'before_xlatex',
    \&dgm_prepare_band_dependencies
);
die "latexmkrc: this latexmk lacks the documented before_xlatex hook\n"
    if !$dgm_hook_registered;
