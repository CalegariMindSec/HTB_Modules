# Introduction to NoSQL Injection

**Module Link**: https://academy.hackthebox.com/module/details/171

### Module Summary

NoSQL is an alternative to traditional SQL databases, and in  this module, we will focus on attacking NoSQL injection vulnerabilities. We will look at MongoDB specifically since it is the most used NoSQL  database in the world.

In this module, we will cover the following:

1. **Introduction**: NoSQL, MongoDB, and NoSQL injection in MongoDB are explained
2. **Basic NoSQL Injection**: We will walk through exploiting two different (basic) NoSQL injection vulnerabilities
3. **Blind Data Exfiltration**: We will cover exploiting two  different blind NoSQL injection vulnerabilities, including writing our  own scripts to automate the process
4. **Tools of the Trade**: We will cover fuzzing, and various public tools commonly used when testing for NoSQL injection vulnerabilities.
5. **Defending against NoSQL Injection**: This chapter covers the 'correct' way to use MongoDB in various languages to avoid NoSQL injections
6. **Skills Assessment**: You are given access to two websites where you must identify and exploit multiple NoSQL injection vulnerabilities alone.

## What is NoSQL Injection?

When `user input` is incorporated into a NoSQL query `without being properly sanitized` first, `NoSQL injection` may occur. If an attacker can control part of the query, they may subvert the logic and get the server to carry out `unintended actions / return unintended results`. Since NoSQL has no standardized query language like SQL [does](https://www.iso.org/obp/ui/#iso:std:iso-iec:9075:-1:ed-5:v1:en), NoSQL injection attacks look different in the various NoSQL implementation.