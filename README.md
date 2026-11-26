# File Identifier

A deployment and investigation of a spoofed file found on a Windows 11 machine. Demonstrating the tool I built 
that checks the file signature specifically the header bytes.


## Purpose

I wanted to develop a better understanding of how spoofed documents and how systems validate whether they are correct or not. What better way than building the tool yourself! This version of the the “FileChecker” is meant to be a basic introduction.

## How it works

This script checks the files ‘magic numbers’ or initial set of hex values against a known list of values that match up to file types. It creates a has to check against VirusTotal for known malicious files and scores the file on how suspicious it might be. Finally it performs a File Analysis grouping all the data and providing a report to the Analyst.

## True Positive
https://github.com/antnycme/CyberSecurity---File-Checker/blob/main/Screenshots/Real.png

## False Positive
