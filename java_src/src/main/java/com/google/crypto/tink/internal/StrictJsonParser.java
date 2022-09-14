/*
 * Copyright 2011 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.crypto.tink.internal;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.TypeAdapter;
import com.google.gson.internal.LazilyParsedNumber;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayDeque;
import java.util.Deque;
import javax.annotation.Nullable;

/**
 * Implementation of a Strict JSON Parser.
 *
 * <p>The parsing is almost identical to TypeAdapters.JSON_ELEMENT, but it rejects duplicated map
 * keys and strings with invalid characters.
 */
public final class StrictJsonParser {

  private static boolean isValidString(String s) {
    int length = s.length();
    int i = 0;
    while (true) {
      char ch;
      do {
        if (i == length) {
          return true;
        }
        ch = s.charAt(i);
        i++;
      } while (!Character.isSurrogate(ch));
      if (Character.isLowSurrogate(ch) || i == length || !Character.isLowSurrogate(s.charAt(i))) {
        return false;
      }
      i++;
    }
  }

  private static final TypeAdapter<JsonElement> JSON_ELEMENT =
      new TypeAdapter<JsonElement>() {
        /**
         * Tries to begin reading a JSON array or JSON object, returning {@code null} if the next
         * element is neither of those.
         */
        @Nullable
        private JsonElement tryBeginNesting(JsonReader in, JsonToken peeked) throws IOException {
          switch (peeked) {
            case BEGIN_ARRAY:
              in.beginArray();
              return new JsonArray();
            case BEGIN_OBJECT:
              in.beginObject();
              return new JsonObject();
            default:
              return null;
          }
        }

        /** Reads a {@link JsonElement} which cannot have any nested elements */
        private JsonElement readTerminal(JsonReader in, JsonToken peeked) throws IOException {
          switch (peeked) {
            case STRING:
              String value = in.nextString();
              if (!isValidString(value)) {
                throw new IOException("illegal characters in string");
              }
              return new JsonPrimitive(value);
            case NUMBER:
              String number = in.nextString();
              return new JsonPrimitive(new LazilyParsedNumber(number));
            case BOOLEAN:
              return new JsonPrimitive(in.nextBoolean());
            case NULL:
              in.nextNull();
              return JsonNull.INSTANCE;
            default:
              // When read(JsonReader) is called with JsonReader in invalid state
              throw new IllegalStateException("Unexpected token: " + peeked);
          }
        }

        @Override
        public JsonElement read(JsonReader in) throws IOException {
          // Either JsonArray or JsonObject
          JsonElement current;
          JsonToken peeked = in.peek();

          current = tryBeginNesting(in, peeked);
          if (current == null) {
            return readTerminal(in, peeked);
          }

          Deque<JsonElement> stack = new ArrayDeque<>();

          while (true) {
            while (in.hasNext()) {
              String name = null;
              // Name is only used for JSON object members
              if (current instanceof JsonObject) {
                name = in.nextName();
                if (!isValidString(name)) {
                  throw new IOException("illegal characters in string");
                }
              }

              peeked = in.peek();
              JsonElement value = tryBeginNesting(in, peeked);
              boolean isNesting = value != null;

              if (value == null) {
                value = readTerminal(in, peeked);
              }

              if (current instanceof JsonArray) {
                ((JsonArray) current).add(value);
              } else {
                if (((JsonObject) current).has(name)) {
                  throw new IOException("duplicate key: " + name);
                }
                ((JsonObject) current).add(name, value);
              }

              if (isNesting) {
                stack.addLast(current);
                current = value;
              }
            }

            // End current element
            if (current instanceof JsonArray) {
              in.endArray();
            } else {
              in.endObject();
            }

            if (stack.isEmpty()) {
              return current;
            } else {
              // Continue with enclosing element
              current = stack.removeLast();
            }
          }
        }

        @Override
        public void write(JsonWriter out, JsonElement value) {
          throw new UnsupportedOperationException("write is not supported");
        }
      };

  public static JsonElement parse(String json) throws IOException {
    try {
      JsonReader jsonReader = new JsonReader(new StringReader(json));
      jsonReader.setLenient(false);
      return JSON_ELEMENT.read(jsonReader);
    } catch (NumberFormatException e) {
      throw new IOException(e);
    }
  }

  /*
   * Converts a parsed {@link JsonElement} into a long if it contains a valid long value.
   *
   * <p>Requires that {@code element} is part of a output produced by {@link #parse}.
   *
   * @throws NumberFormatException if {@code element} does not contain a valid long value.
   *
   */
  public static long getParsedNumberAsLongOrThrow(JsonElement element) {
    Number num = element.getAsNumber();
    if (!(num instanceof LazilyParsedNumber)) {
      // We restrict this function to LazilyParsedNumber because then we know that "toString" will
      // return the unparsed number. For other implementations of Number interface, it is not
      // clearly defined what toString will return.
      throw new IllegalArgumentException("does not contain a parsed number.");
    }
    return Long.parseLong(element.getAsNumber().toString());
  }

  private StrictJsonParser() {}
}
