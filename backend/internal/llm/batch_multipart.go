package llm

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
)

type multipartForm struct {
	form *multipart.Writer
}

func multipartWriter(buf *bytes.Buffer) *multipartForm {
	return &multipartForm{form: multipart.NewWriter(buf)}
}

func (m *multipartForm) WriteField(name, value string) error {
	return m.form.WriteField(name, value)
}

func (m *multipartForm) WriteFile(filename string, content []byte) error {
	part, err := m.form.CreateFormFile("file", filename)
	if err != nil {
		return fmt.Errorf("create form file: %w", err)
	}
	if _, err := io.Copy(part, bytes.NewReader(content)); err != nil {
		return fmt.Errorf("write form file: %w", err)
	}
	return nil
}

func (m *multipartForm) Close() error {
	return m.form.Close()
}

func (m *multipartForm) ContentType() string {
	return m.form.FormDataContentType()
}
