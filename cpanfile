recommends 'Mozilla::CA';

configure_requires 'autodie';
configure_requires 'ExtUtils::CBuilder';
configure_requires 'ExtUtils::MakeMaker::CPANfile';

test_requires 'Test::DescribeMe';
test_requires 'Test::FailWarnings';

requires 'X::Tiny', 0.21;
requires 'Promise::XS';
requires 'parent';
