import 'dart:convert';

import 'utils.dart';

import 'id_token.dart' show JoseHeader;

class LogoutToken {
  final JoseHeader header;
  final String signature;
  final String token;
  final LogoutClaims claims;

  factory LogoutToken.fromString(String token) {
    var parts = token.split('.');
    validate(parts.length == 3, 'id_token string should be 3 parts. '
        'Got ${parts.length} instead');

    var codec = JSON.fuse(UTF8.fuse(BASE64));
    Map header;
    Map body;

    try {
      header = codec.decode(padBase64(parts[0]));
      body = codec.decode(padBase64(parts[1]));
    } catch (e) {
      validate(e == null, 'Error decoding logout token. $e');
    }
    
    return new LogoutToken(token,
        new JoseHeader.fromJson(header),
        new LogoutClaims.fromJson(body), parts[2]);
  }

  LogoutToken(this.token, this.header, this.claims, this.signature);
}

class LogoutClaims {
  static const String _iss = 'iss'; // Required
  static const String _sub = 'sub'; // Optional
  static const String _aud = 'aud'; // Required
  static const String _iat = 'iat'; // Required
  static const String _jti = 'jti'; // Required
  static const String _evt = 'events'; // Required (must also contain key matching _schema below)
  static const String _sid = 'sid'; // Optional
  static const String _schema = 'http://schemas.openid.net/event/backchannel-logout';
  static const String _nonce = 'nonce'; // ERROR if it contains this claim.

  final String issuer;
  final String subject;
  final List<String> audience;
  final DateTime issuedAt;
  final String jwtId;
  final Map<String, dynamic> events;
  final String sessionId;
  final Map<String, dynamic> other;

  factory LogoutClaims.fromJson(Map<String, dynamic> json) {
    String iss = json.remove(_iss);
    validate(iss != null && iss.isNotEmpty, 'Required claim: "$_iss" is null');
    String sub = json.remove(_sub);
    String sid = json.remove(_sid);
    validate((sub == null || sub.isEmpty) && (sid == null || sid.isEmpty),
      'Required claim: "$_sub" and "$_sid" are both null');
    var aud = json.remove(_aud);
    validate(aud != null && aud.isNotEmpty, 'Required claim: "$_aud" is null');
    if (aud is String) {
      aud = [aud];
    }
    int iatsec = json.remove(_iat);
    validate(iatsec != null, 'Required claim: "$_iat" is null');
    DateTime iat = dateFromSeconds(iatsec);
    String jti = json.remove(_jti);
    validate(jti != null && jti.isNotEmpty, 'Required claim: "$_jti" is null');

    Map<String, dynamic> events = json.remove(_evt);
    validate(events != null, 'Required claim: "$_evt" is null');
    validate(events.containsKey(_schema),
        'Required claim "$_evt" does not contain expected schema.');
    String nonce = json.remove(_nonce);
    validate(nonce == null, 'Prohibited claim: "$_nonce" is not null.');

    return new LogoutClaims._(
      issuer: iss,
      subject: sub,
      audience: aud,
      issuedAt: iat,
      jwtId: jti,
      events: events,
      sessionId: sid,
      other: json);
  }

  LogoutClaims._({this.issuer, this.subject, this.audience, this.issuedAt,
              this.jwtId, this.events, this.sessionId, this.other});
}