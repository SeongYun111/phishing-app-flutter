import 'dart:convert';

import 'package:http/http.dart' as http;

class ApiService {
  static const String _baseUrl = 'https://api.maknae.synology.me/api/url/check';

  static Future<Map<String, dynamic>> checkUrl({
    required String url,
    required String sourceApp,
    required String messageText,
  }) async {
    final response = await http.post(
      Uri.parse(_baseUrl),
      headers: {
        'Content-Type': 'application/json',
      },
      body: jsonEncode({
        'url': url,
        'sourceApp': sourceApp,
        'messageText': messageText,
      }),
    );

    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    }

    throw Exception('API error: ${response.statusCode} ${response.body}');
  }
}
