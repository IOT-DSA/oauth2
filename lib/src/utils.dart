// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

/// Adds additional query parameters to [url], overwriting the original
/// parameters if a name conflict occurs.
Uri addQueryParameters(Uri url, Map<String, String> parameters) => url.replace(
    queryParameters: new Map.from(url.queryParameters)..addAll(parameters));

String basicAuthHeader(String identifier, String secret) {
  var userPass = Uri.encodeFull(identifier) + ":" + Uri.encodeFull(secret);
  return "Basic " + BASE64.encode(ASCII.encode(userPass));
}

DateTime dateFromSeconds(int secondsSinceEpoch) =>
    new DateTime.fromMillisecondsSinceEpoch(secondsSinceEpoch * 1000);

String padBase64(String orig) {
  var rem = orig.length % 4;
  if (rem > 0) {
    return orig.padRight(orig.length + (4 - rem), '=');
  }

  return orig;
}

void validate(bool condition, String message) {
  if (condition) return;
  throw new FormatException('Invalid ID Token. $message');
}