# Snort rules advanced parser for pulledpork
This script is intended to be used in conjunction with pulledpork script (https://github.com/shirkdog/pulledpork) to make some adavanced modification, based on regular expression, to the downloaded rules file.

I use this with Security Onion (https://security-onion-solutions.github.io/security-onion/) in /usr/bin/rule-update script after the pulledpork download and before the restart of IDS sensors.

I wrote the script mainly because I get a lot of false positives in SNORT (tto much while enabling Emergin Threats signatures) and to avoid this "noise" I needed some more "precise" rule that triggers alarm only if a service is really and alive.
I found that the pulledpork disablesid.conf, dropsid.conf etc files are not enough for my nneds, so here it is <NOME>

## Install

## Basic Configuration

## Write Custom Rules

## Usage

## Integrate with Secuity Onion
