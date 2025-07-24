# WATR Node - WiFi AI Text Relay

A distributed AI communication system using 802.11 frames for mesh networking with LLM integration.

## Features

- **Custom 802.11 Protocol**: Direct WiFi frame communication bypassing traditional networking
- **Streaming LLM Integration**: Real-time chat streaming using Ollama
- **Dynamic Handler System**: Runtime-loadable message processors
- **Conversation Accumulation**: Automatic assembly of streaming chat segments
- **Heartbeat Management**: Node discovery and health monitoring
- **Async Architecture**: Full async/await support for high performance

## Quick Start

### Prerequisites

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Ollama and a model
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen3:0.6b
```

### Basic Usage

```bash
# Start a WATR node
sudo python main.py wlan0 00:11:22:33:44:55

# With custom settings
sudo python main.py wlan0 00:11:22:33:44:55 --heartbeat-interval 30 --conversation-timeout 300
```

**Note**: Requires root privileges for raw 802.11 frame manipulation.

## File Structure

```
watr-node/
├── main.py                 # Application entry point
├── watr_protocol.py        # Core 802.11 protocol implementation
├── watr_handlers.py        # Dynamic handler system
├── watr_node.py           # High-level node interface
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Architecture

### Core Components

1. **WATRProtocol** (`watr_protocol.py`)
   - Raw 802.11 frame creation and parsing
   - Custom protocol ID (0x8999)
   - Async message queuing and processing

2. **WATRNode** (`watr_node.py`)
   - High-level node interface
   - Heartbeat functionality
   - Handler management
   - LLM integration

3. **Handler System** (`watr_handlers.py`)
   - `WATRHandler` abstract base class
   - `ConversationAccumulatorHandler` for chat assembly
   - `HandlerManager` for dynamic loading

### Message Flow

```
Ollama LLM → Chat Segments → 802.11 Frames → Air → Receiver → Accumulator → Complete Conversation
```

## Usage Examples

### Starting Multiple Nodes

```bash
# Terminal 1 - First node
sudo python main.py wlan0 00:11:22:33:44:55

# Terminal 2 - Second node  
sudo python main.py wlan1 aa:bb:cc:dd:ee:ff
```

### Custom Handler Development

```python
from watr_handlers import WATRHandler
from watr_protocol import WATRMessage

class MyCustomHandler(WATRHandler):
    def get_handled_message_types(self):
        return ['my_message_type']
    
    async def handle_message(self, message: WATRMessage):
        print(f"Custom handler got: {message.payload}")

# Load into node
handler = MyCustomHandler(node)
await node.load_handler("my_handler", handler)
```

### Sending Custom Messages

```python
# Send a custom message
node.send_message('status', {
    'battery': 85,
    'signal_strength': -45,
    'location': {'lat': 40.7128, 'lon': -74.0060}
})

# Send a chat with custom prompt
await node.chat("Explain quantum computing in simple terms")
```

## Configuration

### Command Line Options

- `--heartbeat-interval SECONDS`: Time between heartbeat messages (default: 60)
- `--conversation-timeout SECONDS`: Max time to wait for conversation completion (default: 420)

### Protocol Settings

```python
# In watr_protocol.py
protocol_id = 0x8999  # Custom protocol identifier
```

### WiFi Interface Requirements

- Monitor mode capable WiFi adapter
- Root privileges for frame injection
- Interface must support packet injection

## Message Types

### Built-in Messages

- **heartbeat**: Node health and discovery
- **chat**: Streaming LLM conversations
- **raw**: Fallback for non-JSON data

### Chat Message Format

```json
{
  "type": "chat",
  "payload": {
    "cid": "conversation-uuid",
    "seg": 42,
    "text": "message segment text"
  },
  "timestamp": 1234567890.123,
  "src": "00:11:22:33:44:55",
  "dst": "ff:ff:ff:ff:ff:ff"
}
```

## Conversation Accumulation

The `ConversationAccumulatorHandler` automatically:

1. **Collects** streaming segments by conversation ID
2. **Sorts** segments by sequence number
3. **Timeouts** incomplete conversations (7 min default)
4. **Triggers** completion callbacks with full text
5. **Cleans up** memory and async tasks

### Completion Handler Example

```python
def my_completion_handler(conversation):
    print(f"Complete conversation from {conversation.src_addr}")
    print(f"Duration: {conversation.end_time - conversation.start_time:.1f}s")
    print(f"Text: {conversation.complete_text}")
    
    # Save to database, analyze with AI, etc.
    save_to_database(conversation)

# Register handler
conv_handler.add_completion_handler(my_completion_handler)
```

## Security Considerations

- **Unencrypted**: All messages are sent in plaintext
- **No Authentication**: Any node can send/receive messages
- **Monitoring**: Traffic is visible to WiFi sniffers
- **Injection**: Requires root privileges and monitor mode

**For production use**, add:
- Message encryption
- Node authentication
- Access control
- Rate limiting

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   sudo python main.py ...  # Run with root
   ```

2. **Interface Not Found**
   ```bash
   iwconfig  # List available interfaces
   ```

3. **Monitor Mode Failed**
   ```bash
   sudo airmon-ng start wlan0  # Enable monitor mode
   ```

4. **Ollama Connection Error**
   ```bash
   ollama serve  # Start Ollama server
   ollama pull qwen3:0.6b  # Download model
   ```

### Debug Mode

Add debug prints to see frame traffic:

```python
# In watr_protocol.py
def process_received_frame(self, pkt):
    print(f"DEBUG: Received frame from {pkt[Dot11].addr2}")
    # ... existing code
```

## Development

### Adding New Handlers

1. Extend `WATRHandler`
2. Implement required methods
3. Load with `node.load_handler()`

### Testing

```bash
# Install test dependencies
pip install pytest

# Run tests (when available)
pytest tests/
```

### Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request

## License

This project is provided as-is for research and educational purposes. Use responsibly and in accordance with local regulations regarding WiFi spectrum usage.

## References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Ollama API Reference](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [IEEE 802.11 Standard](https://standards.ieee.org/ieee/802.11/)