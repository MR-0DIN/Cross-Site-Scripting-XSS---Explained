# Cross-Site Scripting (XSS)

> Cross-Site Scripting (XSS) is a web security vulnerability that allows an attacker to inject client-side scripts into web pages into a website, which then gets executed in the victim’s browser.

## Summary
- [Methodology](#methodology)
- [Reflected XSS](#reflected-xss).
  - [What is reflected cross-site scripting?
](#What-is-reflected-cross---site-scripting?)
  - [Impact of reflected XSS attacks
](#Impact-of-reflected-XSS-attacks)
  - [How to find and test for reflected XSS vulnerabilities
](#How-to-find-and-test-for-reflected-XSS-vulnerabilities)
- [Stored XSS](#stored-xss).
  - [What is stored cross-site scripting?
](#What-is-stored-cross---site-scripting?)
  - [Impact of stored XSS attacks
](#Impact-of-stored-XSS-attacks)
  - [How to find and test for stored XSS vulnerabilities
](#How-to-find-and-test-for-stored-XSS-vulnerabilities)
- [DOM-based XSS](#DOM-based-xss).
  - [What is DOM-based cross-site scripting?](#What-is-DOM-based-cross---site-scripting?)
  - [How to test for DOM-based cross-site scripting](#How-to-test-for-DOM---based-cross---site-scripting)
  - [Exploiting DOM XSS with different sources and sinks](#Exploiting-DOM-XSS-with-different-sources-and-sinks)
      -[DOM XSS in jQuery](DOM-XSS-in-jQuery)
      -[DOM XSS in AngularJS](DOM-XSS-in-AngularJS)
  -[Which sinks can lead to DOM-XSS vulnerabilities?](Which-sinks-can-lead-to-DOM---XSS-vulnerabilities?)
