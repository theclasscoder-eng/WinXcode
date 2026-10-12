#pragma once

#include "TextEditor.h"

namespace winx::ide {

// Swift syntax definition for the editor widget. The pointer stays valid for
// the life of the program.
const TextEditor::Language* swift_language();

// Tokenizer pieces, exposed for tests. Each returns the position after the
// token, or `start` when there is no such token at `start`.
TextEditor::Iterator swift_identifier(TextEditor::Iterator start, TextEditor::Iterator end);
TextEditor::Iterator swift_number(TextEditor::Iterator start, TextEditor::Iterator end);
bool swift_punctuation(ImWchar character);

// An Xcode-like dark palette.
TextEditor::Palette editor_palette();

}  // namespace winx::ide
